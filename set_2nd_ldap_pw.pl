#!/usr/local/bin/perl -w
#
use strict;
use Net::LDAP;
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
sub get_4_digit_num;

$|=1;

my %opts;
getopts('ndhfac:p:', \%opts);

exists ($opts{n}) && print "-n used, ldap will not be modified\n";
exists ($opts{d}) && print "-d used, debugging will be printed\n";
exists ($opts{f}) && print "-f used, the most common password will be flushed but no password will be added\n";
exists ($opts{a}) && print "-a used, the common password will be added\n";
exists ($opts{c}) || print_usage();

if (exists $opts{f} && exists $opts{a}) {
    print "-f and -a cannot be specified together\n";
    print_usage();
}

our %cf;
require $opts{c};

exists ($opts{h}) && print_usage();

if (!exists $opts{p}) {
    changePassword(getRandomWord(getWordList()) . get_4_digit_num());
} else {
    changePassword($opts{p});
}

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

sub get_4_digit_num {
    my $n;
    do {
        $n = int(rand(9999));
        print "n: $n\n"
            if (exists $opts{d})
    } while ($n < 1000);
   return $n;
}

sub changePassword {
    my $new_pw = shift;

    print "2nd password: $new_pw\n";

    # common pass that will be replaced
    my $pass_to_replace;
    my %usrs;

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
                            attrs => ["userpassword", "passwordhistory"]);

        $srch->code && die $srch->error;

        # keep count of instances of all passwords, find and record the most common
        my %passwords;

        #	my $user_count = 0;
        my $highest_pw_count = 0;

        foreach my $entry ($srch->entries) {
            my $dn = $entry->dn;
            my @p = ();
            for my $pass ($entry->get_value('userpassword')) {
                if (exists ($passwords{$pass})) { 
                    $passwords{$pass}++;
                } else {
                    $passwords{$pass} = 1;
                }

                if ($passwords{$pass} > $highest_pw_count) {
                    $highest_pw_count = $passwords{$pass};
                    $pass_to_replace = $pass;
                }
                push @{$usrs{$dn}{"pass"}}, $pass;
            }
            push @{$usrs{$dn}{pass}}, undef
                if (!exists($usrs{$dn}{pass}));

            $usrs{$dn}{"pwhistory"} = 0;
            if ($entry->get_value('passwordHistory')) {
                $usrs{$dn}{"pwhistory"} = 1
            }

        }

        # figure out the percentage of accounts containing the common password
        my $percent = 0;
        my $replace_pass = 0; # add (don't replace) a pass by default
        print "highest_pw_count: $highest_pw_count\n";
        if ($highest_pw_count > 1) {
            $percent = ($highest_pw_count / keys %usrs) * 100;
            print "\n";
            print "highest pw count: $highest_pw_count, common hash: $pass_to_replace, percentage of total: $percent\n";
                print "replace_percent is ", $cf{replace_percent}, "\n";

            # if the common pw is greater than $repalce_percent, replace it.
            if ($cf{replace_percent} < $percent) {
                print "common pass will be replaced!";
                $replace_pass = 1;
            } else {
                print "common pass will not be replaced!"
            }
        } else {
            print "no common password was found so won't be replaced.\n";
        }

        my $mod_count=0;

        for my $dn (sort keys %usrs) {
            my @changes;

            # clear existing userpassword and password history
            push @changes, {'delete' => 'passwordHistory'}
                if ($usrs{$dn}{"pwhistory"});
                
            push @changes, {'delete' => 'userpassword'}
                if (defined $usrs{$dn}{"pass"}[0]);

            for my $pw (@{$usrs{$dn}{"pass"}}) {
                next
                    unless defined $pw;
                next
                    if ($replace_pass && ($pass_to_replace eq $pw));
                    
                push @changes, {"add" => {"userpassword" => [$pw]}};
            }
            push @changes, {"add" => {"userpassword" => [$new_pw]}};

            $mod_count++;

            print "\ndn: ", $dn, "\n"
                if (exists $opts{d});

            for my $c (@changes) {
                print "c: ", Dumper $c
                    if (exists $opts{d});
                if (!exists ($opts{n})) { 
                    my $r = $ldap->modify ($dn, %$c);
                    die $r->error		
                        if ($r->code);
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
    print "\nusage: $0 -c config.cf [-e] [-d] [-n] [-h] [-f] [-a] [-p pass]\n";
    print "\t-d print debugging\n";
    print "\t-n print, don't make changes\n";
    print "\t-h print this help message\n";
    print "\t-p use this password instead of generating\n";
    print "\t-f flush password, don't add another secondary password\n";
    print "\t-a delete anyway--delete the most common password even\n";
    print "\t   if it's not in \$cf{replace_percent} of accounts.  This\n";
    print "\t   is useful if a run was interrupted so modified a lot \n";
    print "\t   of accounts but not sufficient replace percentage.\n";
    exit;
}
