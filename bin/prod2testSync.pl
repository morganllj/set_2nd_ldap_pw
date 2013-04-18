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

sub genPCode {
	
	my @wordlist = @_;
	
    my $word = $wordlist[int(rand($#wordlist))];
    while (($word =~ m/[Ll]/)||($word =~ m/[Oo]/)) { 
    	
    		$word = $wordlist[int(rand($#wordlist))];  
    }
    
    my $num = int(rand(9999)) + 1000;
    while (($num =~ m/[0]/)||($num =~ m/[1]/)) { 
    	
    		undef $num;
    		$num = int(rand(9999)) + 1000;  
    }

    return sprintf("%s%04d", $word, $num);
}

sub mailPassword {
	
	my $weekOf = shift;
	my $word = shift;

	my $smtp = Net::SMTP->new("hostname") || die "cannot connect to mailserver";
	$smtp->mail("sun-admin\@domain.org");
	$smtp->recipient("username\@domain.org");
	$smtp->to("alias\@domain.org");
	$smtp->cc("username\@domain.org");
	$smtp->data();
	$smtp->datasend("From: sun-admin\@domain.org\n");
	$smtp->datasend("To: alias\@domain.org\n");
	$smtp->datasend("Cc: username\@domain.org\n");
	$smtp->datasend("Subject: Test LDAP Password for week of: $weekOf\n");
	$smtp->datasend("Hello Developers,\n");
	$smtp->datasend("\n");
	$smtp->datasend("This weeks password for Test LDAP is --> $word\n");
	$smtp->datasend("*****  THIS IS THE REAL PASSWORD FOR THE WEEK! *****\n");
	$smtp->datasend("\n");
	$smtp->datasend("Thanks,\n");
	$smtp->datasend("School Department of Philadelphia\n");
	$smtp->datasend("Technology Services\n");
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
	
		
	$srch = $ldap->search( # perform a search
	
                           base   => "$cf{ldap_base}",
                           filter => "( uid=* )",
                           attrs => "[ ]"
                            
                          );
                      
	$srch->code && die $srch->error;
	
	if (!$srch->entries) { 
		
		 
		$srch = $ldap->unbind; 
		next; 
	}
		
		
	foreach my $entry ($srch->entries) {
			
		my $dn = $entry->dn;
		print "$dn\n";		
						
		my $mesg = $ldap->modify( $dn,
			replace => { userPassword => "$pword" } );
							
		$mesg->code && warn $mesg->error;
	
		
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
my $pword = genPCode(@wordlist);
changePassword($pword);
mailPassword("$mon-$mday-$fyear",$pword);
system("/bin/echo $pword > /path/to/prod2test/archive/$mon-$mday-$fyear.pw");



