### RAS::HiPerARC.pm
### PERL module for accessing a 3Com/USR Total Control HiPerARC
#########################################################

package RAS::HiPerARC;
$VERSION = "1.01";

# The new method, of course
sub new {
   my $class = shift ;
   my $confarray = {} ;
   %$confarray = @_ ;
   bless $confarray ;
}


sub printenv {
   my($confarray) = $_[0];
   print "VERSION = $VERSION\n";
   while (($key,$value) = each(%$confarray)) { print "$key = $value\n"; }
}


sub run_command {
   my($confarray) = shift;
   use Net::Telnet ;
   my($session,@returnlist,$command);

   while ($command = shift) {
      $session = new Net::Telnet;
      $session->errmode("return");
      $session->open($confarray->{hostname});
      $session->login($confarray->{login},$confarray->{password});
      if ($session->errmsg) {
         warn "RAS::HiPerARC ERROR: ", $session->errmsg, "\n"; return();
      }
      $session->print($command);
      my(@output);

      while (1) {
         local($line); $session->print(""); $line = $session->getline ;
         if ($session->errmsg) {
            warn "RAS::HiPerARC ERROR: ", $session->errmsg, "\n"; return();
         }
         if ($line =~ /^HiPer>>\s+/) { $session->print('quit'); $session->close; last; }
         # After the 1st More prompt, the ARC sends
         # ^M\s{a whole line's worth}^M
         # to clear each line for printing
         $line =~ s/^--More--\s+\015?\s*\015?//;
         # Trim off trailing whitespace
         $line =~ s/\s*$/\n/;
         push(@output, $line);
      }

      shift(@output); # Trim the echoed command
      push(@returnlist, \@output);
   } # end of shifting commands

   # We're returning a list of references to lists.
   # Each ref points to an array containing the returned text
   # from the command, and the list of refs corresponds
   # to the list of commands we were given
   return(@returnlist);
} # end of run_command


sub usergrep {
   my($confarray) = $_[0];
   my($username) = $_[1]; return unless $username;
   my(@foo) = &run_command($confarray,'list conn');
   my($output) = shift(@foo);
   my(@ports);

   foreach (@$output) {
      local($port,$user);
      next unless /^slot:\d+\/mod:\d+\s+/;
      $port = unpack("x0 a15", $_) ; $port =~ s/^\s*(\S+)\s*$/$1/;
      $user = unpack("x15 a20", $_); $user =~ s/^\s*(\S+)\s*$/$1/;
      ($user eq $username) && push(@ports,$port);
   }
   return(@ports);
}


sub portusage {
   my($confarray) = $_[0];
   my($interfaces,$connections) = &run_command($confarray,'list interfaces','list connections');
   my(@users);
   my($totalports); $totalports = 0;

   @$interfaces = grep(/^slot:\d+\/mod:\d+\s+/, @$interfaces);

   foreach (@$connections) {
      local($port,$user);
      next unless /^slot:\d+\/mod:\d+\s+/;
      $user = unpack("x15 a20", $_); $user =~ s/^\s*(\S+)\s*$/$1/;
      next if ($user =~ /^\s*$/);
      push(@users,$user);
   }

   return(scalar(@$interfaces),@users);
}


sub userkill {
   my($confarray) = $_[0];
   my($username); $username = $_[1]; return unless $username;
   my(@ports) = &usergrep($confarray,$username);
   return() unless @ports;
   my($resetcmd) = "reset modems " . join(',',@ports);

   &run_command($confarray,$resetcmd);
   return(@ports);
}


#############################################################
1;#So PERL knows we're cool
__END__;

=head1 NAME

RAS::HiPerARC.pm - PERL Interface to 3Com/USR Total Control HiPerARC

Version 1.01, December 20, 1999

Gregor Mosheh (stigmata@blackangel.net)

=head1 SYNOPSIS

B<RAS::HiPerARC> is a PERL 5 module for interfacing with a 3Com/USR Total Control HiPerARC remote access server. Using this module, one can very easily construct programs to find a particular user in a bank of ARCs, disconnect users, get usage statistics, or execute arbitrary commands on a ARC.


=head1 PREREQUISITES AND INSTALLATION

This module uses Jay Rogers' B<Net::Telnet module>. If you don't have B<Net::Telnet>, get it from CPAN or this module won't do much for you.

Installation is easy, thanks to MakeMaker:

=over 4

=item 1.

"perl Makefile.PL && make && make test"

=item 2.

If the tests worked all right, "make install"

=item 3.

Check out the examples in this documentation.

=back

=head1 DESCRIPTION

At this time, the following methods are implemented:

=over 4

=item creating an object with new

Call the new method while supplying the  "hostname", "login", and "password" hash, and you'll get an object reference returned.

   Example:
      use RAS::HiPerARC;
      $foo = new RAS::HiPerARC(
         hostname => 'dialup1.example.com',
         login => '!root',
         password => 'mysecret'
      );


=item printenv

This is for debugging only. It prints to STDOUT a list of its configuration hash, e.g. the hostname, login, and password. The printenv method does not return a value.

   Example:
      $foo->printenv;


=item run_command

This takes a list of commands to be executed on the ARC, connects to the ARC and executes the commands, and returns a list of references to arrays containg the text of each command's output. 

Repeat: It doesn't return an array, it returns an array of references to arrays. Each array contains the text output of each command. Think of it as an array-enhanced version of PERL's `backtick` operator.

   Example:
      # Execute a command and print the output
      $command = 'list conn';
      ($x) = $foo->run_command($command);
      print "Output of command \'$command\':\n", @$x ;

   Example:
      # Execute a string of commands
      # and show the output from one of them
      (@output) = $foo->run_command('list interface','list con');
      print "Modems:\n@$output[0]\n\n";;
      print "Current connections:\n@$output[1]\n\n";;


=item usergrep

Supply a username as an argument, and usergrep will return an array of ports on which that user was found. Internally, this does a run_command("list connections") and parses the output.

   Example:
      @ports = $foo->usergrep('gregor');
      print "User gregor was found on ports @ports\n";


=item userkill

This does a usergrep, but with a twist: it disconnects the user by resetting the modem on which they're connected. Like usergrep, it returns an array of ports to which the user was connected before they were reset.  This is safe to use if the specified user is not logged in.

   Examples:
      @foo = $foo->userkill('gregor');
      print "Gregor was on ports @foo - HA HA!\n" if @ports ;

      @duh = $foo->userkill('-');
      print "There were ", scalar(@duh), " ports open.\n";


=item portusage

This returns an array consisting of 2 items: The 1st element is the number of ports. The rest is a list of users who are currently online.

   Examples:
      ($ports,@people) = $foo->portusage;
      print "There are $ports total ports.\n";
      print "There are ", scalar(@people), "people online.\n";
      print "They are: @people\n";

      ($ports,@people) = $foo->portusage;
      print "Ports free: ", $ports - scalar(@people), "\n";
      print "Ports used: ", scalar(@people), "\n";
      print "Ports total: ", $ports, "\n";


=head1 EXAMPLE PROGRAMS

portusage.pl - Prints a summary of port usage on a bank of modems

use RAS::HiPerARC;
$used = $total = 0;
foreach ('arc1.example.com','arc2.example.com','arc3.example.com') {
   $foo = new RAS::HiPerARC(
      hostname => $_,
      login => '!root',
      password => 'mysecret'
   );

   local($ports,@ports) = $foo->portusage;
   $total += $ports;
   $used += scalar(@ports);
}

print "$used out of $total ports are in use.\n";

###

usergrep.pl - Finds a user on a bank of modems

($username) = @ARGV;
die "Usage: $0 <username>\nFinds the specified user.\n" unless $username ;

use RAS::HiPerARC;
foreach ('arc1.example.com','arc2.example.com','arc3.example.com') {
   $foo = new RAS::HiPerARC(
      hostname => $_,
      login => '!root',
      password => 'mysecret'
   );

   @ports = $foo->usergrep($username);
   (@ports) && print "Found user $username on $_ ports @ports\n";
}

###

userkill.pl - Kick a user off a bank of modems. Makes a great cron job. ;)

($username) = @ARGV;
die "Usage: $0 <username>\nDisconnects the specified user.\n" unless $username ;

use RAS::HiPerARC;
foreach ('arc1.example.com','arc2.example.com','arc3.example.com') {
   $foo = new RAS::HiPerARC(
      hostname => $_,
      login => '!root',
      password => 'mysecret'
   );

   @ports = $foo->userkill($username);
   (@ports) && print "$_ : Killed ports @ports\n";
}


=head1 CHANGES IN THIS VERSION

1.01     Added a test suite. Corrected some errors in the documentation. Improved error handling a bit.

=head1 BUGS

Since we use this for port usage monitoring, new functions will be added slowly on an as-needed basis. If you need some specific functionality let me know and I'll see what I can do. If you write an addition for this, please send it in and I'll incororate it and give credit.

I make some assumptions about router prompts based on what I have on hand for experimentation. If I make an assumption that doesn't apply to you (e.g. all prompts are /^[a-zA-Z0-9]+\>\s+$/) then it can cause two problems: pattern match timed out or a hang when any functions are used. A pattern match timeout can occur because of a bad password or a bad prompt. A hang is likely caused by a bad prompt. Check the regexps in the loop within run_command, and make sure your prompt fits this regex. If not, either fix the regex and/or (even better) PLEASE send me some details on your prompt and what commands you used to set your prompt. If you have several routers with the same login/password, make sure you're pointing to the right one. A Livingston PM, for example, has a different prompt than a HiPerARC - if you accidentally point to a ARC using RAS::PortMaster, you'll likely be able to log in, but run_command will never exit, resulting in a hang.


=head1 LICENSE AND WARRANTY

Where would we be if Larry Wall were tight-fisted with PERL itself? For God's sake, it's PERL code. It's free!

This software is hereby released into the Public Domain, where it may be freely distributed, modified, plagiarized, used, abused, and deleted without regard for the original author.

Bug reports and feature requests will be handled ASAP, but without guarantee. The warranty is the same as for most freeware:
   It Works For Me, Your Mileage May Vary.

=cut

