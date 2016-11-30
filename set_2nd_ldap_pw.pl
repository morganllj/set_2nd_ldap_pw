#!/usr/bin/perl -w
#

use strict;
use Net::LDAP;
use Config::Fast;
$Config::Fast::Arrays = '1';
use Net::SMTP;
use Digest::SHA1;
use MIME::Base64;
use Getopt::Std;
use File::Basename;
use Data::Dumper;

sub print_usage;

$|=1;

our %cf = fastconfig();
our $script = "$cf{scriptname}";

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
	
		$word = $word . $charc;
	}
	return $word;
}


sub getWordList {
    my $subname = "getWordList";
    my @wordlist;
	
    #open(WORDLIST, "$cf{basedir}/etc/wordlist.txt") or die "$subname: can't open wordlist.txt : $!";

    my $wordlist_dir = dirname($0) . "/../etc";
    #open(WORDLIST, $wordlist_dir . "/wordlist.txt") or die "$subname: can't open wordlist.txt : $!";
    my $wordlist = $wordlist_dir . "/wordlist.txt";
    print "open wordlist: ", $wordlist, "\n"
      if (exists $opts{d});
    open(WORDLIST, $wordlist_dir . "/wordlist.txt") or die "$subname: can't open $wordlist : $!";
    
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
    $ctx->add($password);
    $ctx->add($salt);

    return ('{SSHA}' . encode_base64($ctx->digest . $salt, ''), $password);
}



sub mailPassword {
	
	my $weekOf = shift;
	my $word = shift;

	my $smtp = Net::SMTP->new("smtp.domain.org") || die "cannot connect to mail server smtp.domain.org";

	$smtp->mail();
#	$smtp->to("alias\@domain.org");
	$smtp->to("morgan\@domain.org");
	$smtp->data();
	$smtp->datasend("From: alias\@domain.org\n");
	$smtp->datasend("To: alias\@domain.org\n");
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
		
#	my $filter = "(&(|(objectclass=orgEmployee)(objectclass=orgAssociate)(objectclass=orgExternalEmployee))(!(orgHomeOrgCD=9500))(!(orgHomeOrgCD=9HF0))(!(orgHomeOrgCD=9420))(!(orgHomeOrgCD=9050))(!(orgHomeOrgCD=9820))(!(orgHomeOrgCD=9MV0)))";
	my $filter = "(|(uid=morgan)(uid=kacless))";
	print "\nsearching: $filter\n"
	  if (exists($opts{d}));
	$srch = $ldap->search( # perform a search
                           base   => "$cf{ldap_base}",
                           filter => $filter,
                           attrs => "[ 'userpassword' ]");
                      
	$srch->code && die $srch->error;

	# keep count of instances of all passwords
	my %passwords;
	my $user_count = 0;
	foreach my $entry ($srch->entries) {
	    $user_count++;
	    my @pass = $entry->get_value('userpassword');
	    for my $pass (@pass) {
		if (exists ($passwords{$pass})) { 
		    $passwords{$pass}++;
		} else {
		    $passwords{$pass} = 1;
		}
	    }
	}

	# find the most common pass and it's count
	my ($count, $pass_to_replace);
	$count=0;
	for my $k (keys %passwords) {
	    if ($passwords{$k} > $count) {
		$pass_to_replace = $k;
		$count = $passwords{$k};
	    }
	}

	# go through one more time and make sure the most common pass
	# we found is in fact the most common
	for my $k (keys %passwords) {
	    if ($passwords{$k} >= $count && ($k ne $pass_to_replace)) {
		$pass_to_replace = undef;
		$count = 0;
	    }
	}

	print "passwords: ", Dumper %passwords;

	my $percent;
	if ($count > 0) {
#	    $percent = ($count / scalar (keys %passwords)) * 100;
	    $percent = ($count / $user_count) * 100;
	
	    print "most common hash: $count, $pass_to_replace, percentage of total: $percent\n"
	      if (exists $opts{d});
	} else {
	    print "no common password was found and thus won't be removed.\n";
	}

	foreach my $entry ($srch->entries) {
	    my $dn = $entry->dn;

	    my @saved_pws;

	    my @pass = $entry->get_value('userpassword');
	    for my $pass (@pass) {
		# We store passwords in the user entry that are not
		# the common pass--common pass must be in 99% of users
		# or the userneeds to specify -a to pull most
		# common pass regardless
		push @saved_pws, $pass
		  unless (($count > 1 && $pass eq $pass_to_replace) && ($percent > 99 || exists $opts{a}));
	    }

	    print "$dn\n"
	      if (exists $opts{d});

	    print "\tdeleting passwordHistory\n"
	      if (exists $opts{d});
	    if (!exists $opts{n}) {
		my $r = $ldap->modify ($dn, delete => ['passwordHistory']);
		if ($r->code) {
		    die $r->error
		      unless ($r->error =~ /No such attribute/);
		}
		  
	    }

	    print "\tdeleting userPassword\n"
	      if (exists $opts{d});
	    if (!exists $opts{n}) {
		my $r = $ldap->modify ($dn, delete => ['userPassword']);
		$r->code && die $r->error;
	    }

	    print "\tadding/re-adding userpassword\n"
	      if (exists $opts{d});

	    if (exists $opts{d}) {
		for my $p (@saved_pws) {
		    print "\t\tadding $p\n";
		}
	    }
	    
	    if (!exists $opts{f}) {
		print "\t\tadding $pword..\n"
		  if (exists $opts{d});
		push @saved_pws, $pword;
	    }

	    if (!exists ($opts{n})) {
		my $r = $ldap->modify ($dn, add => {userpassword => \@saved_pws});
		$r->code && die $r->error;
	    }

	    # if (!exists $opts{f}) {
	    # 	# # print "$dn\n"
	    # 	# #   if (exists $opts{d});
	    # 	# print "\tadding $pword..\n"
	    # 	#   if (exists $opts{d});
	    # 	# if (!exists ($opts{n})) {
	    # 	#     my $r = $ldap->modify ($dn, add => {userpassword => $pword});
	    # 	#     $r->code && die $r->error;
	    # 	# }
	    # }
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
print "new hash and password: /$hash/, /$pword/\n\n";
changePassword($hash);

my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
$mon = $mon + 1;
$mon = "0$mon"
  if (length($mon)  == 1);
$mday = "0$mday"
  if (length($mday) == 1);
$hour = "0$hour"
  if (length($hour) == 1);
$min = "0$min"
  if (length($min)  == 1);
$sec = "0$sec"
  if (length($sec)  == 1);
my $fyear = $year + 1900;

if (!exists $opts{f}) {    
    mailPassword("$mon-$mday-$fyear",$pword);
    # system("/bin/echo $pword > /path/to/prod2test-ldaptest/archive/$mon-$mday-$fyear.pw");
    # system("/bin/echo $pword > $cf{basedir}/archive/$mon-$mday-$fyear.pw");

    my $archive_file = dirname($0) . "/../archive/${fyear}${mday}${mon}${hour}${mon}${sec}_pass.txt";
    print "opening archive file ", $archive_file, "\n"
      if (exists $opts{d});
    # open OUT, basename($0) . $archive_file || warn "problem opening $archive_file";
    open OUT, ">", $archive_file || warn "problem opening $archive_file";
    print OUT "$pword\n";
    close (OUT);      
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
