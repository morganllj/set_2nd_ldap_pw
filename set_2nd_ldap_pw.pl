#!/usr/bin/perl -w
#

use strict;
use Net::LDAP;
use Net::SMTP;
use Digest::SHA1;
use MIME::Base64;
use Getopt::Std;
use File::Basename;
use Data::Dumper;

sub genPassword;
sub getWordList;
sub getRandomWord;
sub genPCode;
sub mailPassword;
sub changePassword;
sub print_usage;

$|=1;

my %opts;
getopts('ndhfac:', \%opts);

exists ($opts{n}) && print "-n used, ldap will not be modified\n";
exists ($opts{d}) && print "-d used, debugging will be printed\n";
exists ($opts{f}) && print "-f used, the most common password will be flushed but no password will be added\n";
exists ($opts{a}) && print "-a used, the common password will be added\n";
exists ($opts{c}) || print_usage();

if (exists $opts{f} && exists $opts{a}) {
    print "-f and -a cannot be specified together\n";
    print_usage();
}

print "\n";

our %cf;
require $opts{c};
my $percent;

exists ($opts{h}) && print_usage();


my @wordlist = getWordList ();
my ($pw_hash, $pword) = genPCode(@wordlist);
print "generated 2nd password: $pword\n";
changePassword($pw_hash);

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

if ((!exists $opts{f} && $percent > $cf{"replace_percent"}) || (!exists $opts{f} && exists $opts{a})) {
    print "emailing password\n"
      if (exists($opts{d}));
    mailPassword("$mon-$mday-$fyear",$pword);

    my $archive_file = dirname($0) . "/archive/${fyear}${mday}${mon}${hour}${mon}${sec}_pass.txt";
    print "opening archive file ", $archive_file, "\n"
      if (exists $opts{d});

    open OUT, ">", $archive_file or warn "problem opening $archive_file";
    print OUT "$pword\n";
    close (OUT);      
}


sub genPassword {
	my $word;

	for ( 1 .. 10 ) {
		my @alpha = (1 .. 10, "a" .. "z", "A" .. "Z");
		my $char = $alpha[int(rand($#alpha))];
	
		$word = $word . $char;
	}
	return $word;
}


sub getWordList {
    my @wordlist;
	
    my $wordlist_dir = dirname($0);
    my $wordlist = $wordlist_dir . "/wordlist.txt";
    print "opening wordlist: ", $wordlist, "\n";
    open(WORDLIST, $wordlist_dir . "/wordlist.txt") or die "can't open $wordlist : $!";
    
    while(<WORDLIST>) {
        chomp;
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

	my $smtp = Net::SMTP->new($cf{"smtp_server"}) || die "cannot connect to mail server ", $cf{"smtp_server"};

	$smtp->mail();
	$smtp->to($cf{"notification_email_to"});
	$smtp->data();
	$smtp->datasend("From: ", $cf{"notification_email_frm"},"\n");
	$smtp->datasend("To: ", $cf{"notification_email_to"},"\n");
	$smtp->datasend("Subject: test Password for week of: $weekOf\n");
	$smtp->datasend("\n");
	$smtp->datasend("This weeks password for test ldap is --> $word\n");
	$smtp->datasend("*****  THIS IS THE REAL PASSWORD FOR THE WEEK! *****\n");
	$smtp->datasend("\n");
	$smtp->dataend();
	$smtp->quit();
}

sub changePassword {
    my $pword = shift;

    for my $l (@{$cf{ldap_list}}) {
	print "\n";
	print "connecting to ", $l->{ldap_server}, "\n";
	my $ldap = Net::LDAP->new( "$l->{ldap_server}" ) or die "$@";
		
	my $srch = $ldap->bind( $l->{ldap_bind_dn}, password => $l->{ldap_bind_dn_pw});

	my $filter = $l->{"ldap_filter"};
	print "searching: $filter\n";
	$srch = $ldap->search( # perform a search
                           base   => $l->{ldap_base},
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

	# find the most common pass and its count
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

	$percent = 0;
	if ($count > 0) {
	    $percent = ($count / $user_count) * 100;

	    print "\n";
	    print "most common hash: $count, $pass_to_replace, percentage of total: $percent\n";
	    print "replace_percent is ", $cf{replace_percent}, "\n";
	} else {
	    print "no common password was found and thus won't be removed.\n";
	    if (!exists $opts{a}) {
		print "nothing to be done, exiting.\n";
		exit;
	    }

	}

	my $mod_count=0;
	foreach my $entry ($srch->entries) {
	    my $dn = $entry->dn;

	    my @saved_pws;

	    my @pass = $entry->get_value('userpassword');
	    for my $pass (@pass) {
		# save all passwords in the user account except the
		# common password.  Treat the common password as a
		# saved pass if the replace_percent is not reached but
		# the user has not requested a flush
		unless ($pass eq $pass_to_replace && ($percent > $cf{"replace_percent"} || exists $opts{f})) {
		    push @saved_pws, $pass
		}
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
		if ($r->code) {
		    die $r->error
		      unless ($r->error =~ /No such attribute/);
		}
	    }

	    print "\tadding/re-adding userpassword\n"
	      if (exists $opts{d});

	    if (exists $opts{d}) {
		for my $p (@saved_pws) {
		    print "\t\tadding $p\n";
		}
	    }

	    # only put in the new 2nd pass if a high enough percent or requested by the user
	    if ((!exists $opts{f} && $percent > $cf{"replace_percent"}) || (!exists $opts{f} && exists $opts{a})) {
		print "\t\tadding 2nd pass $pword..\n"
		  if (exists $opts{d});
		push @saved_pws, $pword;
	    }
	    $mod_count++;
	    if (!exists ($opts{n})) {
		my $r = $ldap->modify ($dn, add => {userpassword => \@saved_pws});
		if ($r->code) {
		    die $r->error
		      unless ($r->error =~ /no values given/);
		}

	    }
	}
	
	$srch = $ldap->unbind;

	print "\n";
	print "read-only, would have "
	  if (exists $opts{n});
	print "added ", $mod_count, " second passwords.\n";
    }
}


sub print_usage {
    print "\nusage: $0 -c config.cf [-d] [-n] [-h] [-f] [-a]\n";
    print "\t-d print debugging\n";
    print "\t-n print, don't make changes\n";
    print "\t-h print this help message\n";
    print "\t-f flush password, don't add another secondary password\n";
    print "\t-a delete anyway--delete the most common password even\n";
    print "\t   if it's not in \$cf{replace_percent} of accounts.  This\n";
    print "\t   is useful if a run was interrupted so modified a lot \n";
    print "\t   of accounts but not sufficient replace percentage.\n";
    exit;
}
