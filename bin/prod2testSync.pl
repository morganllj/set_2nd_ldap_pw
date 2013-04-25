#!/usr/bin/perl
#############################################
## History ##################################
#
#
#############################################
## Includes #################################
use strict;
use Net::LDAP;
use Config::Fast;
$Config::Fast::Arrays = '1';
use Net::SMTP;
use Digest::SHA1;
use MIME::Base64;
use Getopt::Std;

sub print_usage;

$|=1;

############################################
## Globals #################################
our %cf = fastconfig();
our $script = "$cf{scriptname}";
our ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
our $mon = $mon + 1;
if (length($mon)  == 1) {$mon = "0$mon";}
if (length($mday) == 1) {$mday = "0$mday";}
if (length($hour) == 1) {$hour = "0$hour";}
if (length($min)  == 1) {$min = "0$min";}
if (length($sec)  == 1) {$sec = "0$sec";}
our $fyear = $year + 1900;

###########################################

my %opts;
getopts('ndhfa', \%opts);

exists ($opts{n}) && print "-n used, ldap will not be modified\n";
exists ($opts{d}) && print "-d used, debugging will be printed\n";
exists ($opts{f}) && print "-f used, the most common password will be flushed but no password will be added\n";
exists ($opts{a}) && print "-a used, the common password will be deleted even if it's below 99%\n";

exists ($opts{h}) && print_usage();

sub genPassword {
	
	my $word;
	
	for ( 1 .. 10 ) {
		
		my @alpha = (1 .. 10, "a" .. "z", "A" .. "Z");
		my $charc = $alpha[int(rand($#alpha))];
	
		#print "$charc\n";
		$word = $word . $charc;
	}
	
	#print "$word\n";
	return $word;
}


sub getWordList {
	
	my $subname = "getWordList";
	my @wordlist;
	
    open(WORDLIST, "$cf{basedir}/etc/wordlist.txt") or die "$subname: can't open wordlist.txt : $!";
    
    while( <WORDLIST> ) {
        chomp($_);
        push(@wordlist, $_);
    }
    
    close(WORDLIST);
    
    return (@wordlist);
}


sub getRandomWord {
    my @wordlist = @_;

    my $word = $wordlist[int(rand($#wordlist))];
    while (($word =~ m/[Ll]/)||($word =~ m/[Oo]/)) { 
    	
    		$word = $wordlist[int(rand($#wordlist))];  
    }


    return $word;
}

sub genPCode {
    my @wordlist = @_;
	
    my $word = getRandomWord(@wordlist);
    my $salt = getRandomWord(@wordlist);
    
    my $num = int(rand(9999)) + 1000;
    while (($num =~ m/[0]/)||($num =~ m/[1]/)) { 
    	
    		undef $num;
    		$num = int(rand(9999)) + 1000;  
    }
    my $password = sprintf("%s%04d", $word, $num);

    my $ctx = Digest::SHA1->new;
    $ctx->add($salt);
    $ctx->add($password);

    return ('{SSHA}' . encode_base64($ctx->digest . $salt, ''), $password);
}



sub mailPassword {
	
	my $weekOf = shift;
	my $word = shift;

	my $smtp = Net::SMTP->new("smtp.domain.org") || die "cannot connect to mail server smtp.domain.org";


	$smtp->mail();
	$smtp->to("dsadmin\@domain.org");
	$smtp->data();
	$smtp->datasend("From: alias\@domain.org\n");
	$smtp->datasend("To: dsadmin\@domain.org\n");
	$smtp->datasend("Subject: test.domain.net Password for week of: $weekOf\n");
	$smtp->datasend("Hello Developers,\n");
	$smtp->datasend("\n");
	$smtp->datasend("This weeks password for testldap.domain.net is --> $word\n");
	$smtp->datasend("*****  THIS IS THE REAL PASSWORD FOR THE WEEK! *****\n");
	$smtp->datasend("\n");
	$smtp->datasend("Thanks,\n");
	$smtp->datasend("Technology Services\n");
	$smtp->datasend("Org Name here\n");
	$smtp->dataend();
	$smtp->quit();

}

sub changePassword {
	
	my $pword = shift;
	my $subname = "changePassword";
			
	my $ldap = Net::LDAP->new( "$cf{ldap_server}" ) or die "$@";
		
	my $srch = $ldap->bind( "$cf{ldap_bind_dn}",
                        		password => "$cf{ldap_bind_dn_pw}"
                        );
	
		
	my $filter = "(&(|(objectclass=orgEmployee)(objectclass=orgAssociate)))";
	print "\nsearching: $filter\n"
	  if (exists($opts{d}));
	$srch = $ldap->search( # perform a search
                           base   => "$cf{ldap_base}",
                           filter => $filter,
                           attrs => "[ 'userpassword' ]"
                            
                          );
                      
	$srch->code && die $srch->error;
	
	# unnecessary, I think.  mj.
	# if (!$srch->entries) { 
	# 	$srch = $ldap->unbind; 
	# 	next; 
	# }

	my %passwords;
	foreach my $entry ($srch->entries) {
	    my @pass = $entry->get_value('userpassword');
	    for my $pass (@pass) {
		if (exists ($passwords{$pass})) { 
		    $passwords{$pass}++;
		} else {
		    $passwords{$pass} = 1;
		}
	    }
	}

	my ($count, $pass_to_replace);
	$count=0;
	for my $k (keys %passwords) {
	    if ($passwords{$k} > $count) {
		$pass_to_replace = $k;
		$count = $passwords{$k};
	    }

	}

	my $percent = ($count / scalar (keys %passwords)) * 100;
	print "most common hash: $count, $pass_to_replace, percentage of total: $percent\n"
	  if (exists $opts{d});

	foreach my $entry ($srch->entries) {
	    my $dn = $entry->dn;

	    if ($percent > 99 or exists $opts{a}) {  # if 99% of entries have a common
                                  # password then remove that password
                                  # as it's the old fall through
                                  # password
		my @pass = $entry->get_value('userpassword');
		for my $pass (@pass) {
		    if ($pass eq $pass_to_replace) {
			print "$dn\n"
			  if (exists $opts{d});
			print "\tdeleting $pass..\n"
			  if (exists $opts{d});
			if (!exists $opts{n}) {
			    my $r = $ldap->modify($dn, delete => {userpassword => $pass});
			    $r->code && due $r->error;
			}
		    }
		}
	    }
	    if (!exists $opts{f}) {
		print "$dn\n"
		  if (exists $opts{d});
		print "\tadding $pword..\n"
		  if (exists $opts{d});
		if (!exists ($opts{n})) {
		    my $r = $ldap->modify ($dn, add => {userpassword => $pword});
		    $r->code && due $r->error;
		}
	    }
	}
	
	$srch = $ldap->unbind;	
	
	return 0;
}

###################################################
### Main ##########################################

### Synchronize people entries


### Change Password
######my $pword = genPassword();
my @wordlist = getWordList ();
my ($hash, $pword) = genPCode(@wordlist);
print "new hash and password: /$hash/, /$pword/\n\n"
  if (exists $opts{d});
#changePassword($pword);
changePassword($hash);
if (!exists $opts{f}) {
    mailPassword("$mon-$mday-$fyear",$pword);
    system("/bin/echo $pword > /path/to/prod2test-ldaptest/archive/$mon-$mday-$fyear.pw");
    system("/bin/echo $pword > $cf{basedir}/archive/$mon-$mday-$fyear.pw");
}



sub print_usage {
    print "\n\nusage: $0 [-d] [-n] [-h] [-f] [-a]\n";
    print "\t-d print debugging\n";
    print "\t-n print, don't make changes\n";
    print "\t-h print this help message\n";
    print "\t-f flush password, don't add another secondary password\n";
    print "\t-a delete anyway--delete the most common password even if it's not in 99% of accounts\n";
    print "\t   this is useful if a run was interrupted so modified a lot of accounts but not 99%.\n";
    exit;
}
