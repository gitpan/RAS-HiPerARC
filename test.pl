#!/usr/bin/perl
# test script for RAS::HiPerARC
#######################################################


### Get the username to seek/kill with the usergrep()
### and userkill() functions

print <<EOF;

Test Suite for RAS::HiPerARC
EOF

### Get the list of ARCs to scan/test
print <<EOF;

The tests will connect to a HiPerARC
and run some benign commands to verify that 
things are working properly.
Enter the hostname or IP address of a
HiPerARC that will be used for the tests.
Enter nothing to skip the tests.
EOF

print "Hostname or IP of ARC: ";
chomp($pm = <STDIN>);
exit unless $pm;


print <<EOF;

Please enter the username and password used to
log into the ARC for the tests. This user should 
be able to login to the ARC and get a command prompt.
EOF

print "Login name for ARC: ";
chomp($login = <STDIN>);
print "Password for ARC: ";
chomp($password = <STDIN>);


print <<EOF;

The usergrep() test looks for a specified user on a bank
of RAS devices. The userkill() function will look for
the specified user and knock them offline.
Specify here the user that will be located
and terminated. Enter nothing for these tests
to be skipped.
EOF

print "Username for seek/kill tests: ";
chomp($testuser = <STDIN>);
print "\n\n";


######################################################
### And now that we have our data, the actual tests

use RAS::HiPerARC;

### Create a new instance
print "### Testing new() method for host $_\n\n";
$foo = new RAS::HiPerARC(
   hostname => $pm,
   login => $login,
   password => $password,
);
die "ERROR: Couldn't create object. Stopped " unless $foo;
print "OK.\n\n";

print "### Testing the printenv() method:\n";
$foo->printenv;
print "\n\n";

print "### Testing the run_command() method:\n";
($x,$y) = $foo->run_command('list ip routes','show user default');
print "Output of \'list ip routes\' on $_:\n@$x\n\n";
print "Output of \'show user default\' on $_:\n@$y\n\n";

print "### Testing portusage() method:\n";
@x = $foo->portusage;
print "There are ", shift(@x), " modems in all.\n";
print "There are ", scalar(@x), " users online. ";
print "They are:\n@x\n\n";

if ($testuser) {
   print "### Testing usergrep() method on user $testuser\n";
   @x = $foo->usergrep($testuser);
   print "Found user $testuser on $pm ports: @x\n\n" if @x;
}
else { print "### Skipping usergrep() test\n"; }

if ($testuser) {
   print "### Testing userkill() method on user $testuser\n";
   @x = $foo->userkill($testuser);
   print "Killed user $testuser on $pm ports: @x\n\n" if @x;
}
else { print "### Skipping userkill() test\n"; }

print "Finished with tests.\n";


