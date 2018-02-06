use strict;
use warnings;

use File::Basename;
use Getopt::Long;
use Pod::Usage;

my $VERSION = 19;

## GLOBALS SET BY COMMAND LINE ARGUMENTS

# glob to include more files
my $glob_files;
# filter files with a callback passed via commandline and evaluated in check_args
my $filter_files;
# string used to display the sub
my $filter_files_string;
# files to be scanned
my @files;
# command output instead of logfiles
my $command;
# command has it's handle
my $cmd_handle;
# valid lines must match:
my $valid_rex;
# line will by splitted based on:
my $rec_sep;
# the remote IP is found at position (from 0):
my $ip_pos;
# max occurences admitted
my $max_occ = 50;
# refresh interval in seconds
my $wait = 5;
# dry run as default
my $effectively_run = 0;
# discount on occurences after a block
my $discount = $max_occ;
# duration of the block in second
my $block_dur = 300;
# block rule template
my $block_rule;
# unblock rule template
my $unblock_rule;
# file to write logs
(my $log_file = basename($0)) .='.log';
# white list
my @wlist;
my %white_list;
# garbage is collected in a separte file
my $garbage = 0;
# verbosity
my $verbosity = 0;
# $help
my $help = 0;

$SIG{INT} = \&clean_up;
$SIG{TERM} = \&clean_up;
$SIG{HUP} = \&clean_up;
$SIG{KILL} = \&clean_up;

BEGIN {
    if ($^O eq 'MSWin32'){
        # very dirty but effective way to check administrative rights
        system 'net session > nul 2>&1';
        die "ERROR: $0 need administrative rights to be run\n" unless $? == 0;
        system 'sc interrogate MpsSvc > nul 2>&1';
        die "ERROR: MpsSvc (aka Win32 firewall) not running\n" unless $? == 0;
    }
    elsif($^O eq 'linux'){
        # check for root
        die "ERROR: $0 need administrative rights to be run\n" unless $> == 0;
        system ' 2>/dev/null 1>&2 iptables -L';
        # only a warning for Linux users
        print "WARNING is iptables running?\n" unless $? == 0;
    }
    else {
        print "$^O not yet supported!\n";
        exit 1;
    }

}

# parse the arguments
check_args();
# open logfile for write
open my $output, '>>', $log_file or die "ERROR unable to open $log_file for appending.";
# be sure that everything is in the logfile
		$output->autoflush(1);#v17
select $output;
# expand the glob for first time (glob will be rerun every iteration)
@files = glob($glob_files);
# verify that regexes given in command line compile correctly
map { eval {$_ = qr/$_/} } $valid_rex,$rec_sep;
die qq(ERROR compiling regex:[$_]\n$@\n) if $@;
# exit unless all requirements are met
check_config();
# garbage lines collection
my $garb;
if ($garbage){
    (my $garb_file = $log_file) .='.garbage';
    open $garb, '>', $garb_file or die "ERROR unable to open $garb_file for writing.";
}

# print header and configuration
biprint ( show_config() ) if $verbosity > 1;

## GLOBALS

# cache of Ips to be blocked
my %ip;
# the count of IP that exceeded the maximum allowed number of occurences
my %ip_count;
# jobs contains the IP, the type (block and unblock) and time when trigger
my %job;
# file yet visited are sored here, also last line number and modification time
# filename => [mtime lastreadline]
my %visited_files;
# white list must be converted to an hash
map {$white_list{$_} = 1} @wlist;

## MAIN LOOP

while (1) {
		biprint ("\n",scalar localtime(time)."\n") if $verbosity > 1;
		# get relevants lines from command output
		if ($command){ proc_command();  }
		# or from logfiles
		else {
			my @files  = grep {$filter_files->($_)} glob $glob_files;
			biprint (scalar @files, " files to process (".(join ' ',@files),")\n")  if $verbosity > 1;
			if (scalar @files){
				tell_files( @files );
			}
			else{
				sleep 1 for 1..$wait;
				next;
			}
			
		}
		# caches are full, go enqueing jobs
		&enq_jobs;
		if ($verbosity > 2) {
		  biprint ("IP global occurrences history (more than $max_occ times):\n");
		  biprint (
		  map {qq($_\t\t$ip_count{$_}\n)}
			  sort { $ip_count{$a} <=> $ip_count{$b} } keys %ip_count
		  );
		  biprint("\n");
		}
		# executon time
		&exec_jobs;
		biprint ( "\n".(scalar keys %job).
				" jobs pending:\n") if $verbosity > 1;
		biprint (map {"$_ ".scalar localtime($job{$_})."\n"}
				sort { $job{$a} <=> $job{$b}} keys %job) if $verbosity > 2;

		#Setting the environment variable PERL_SIGNALS=unsafe allows ^C to interupt sleep.
		#from http://www.perlmonks.org/?node=552515
		sleep 1 for 1..$wait;
}
################################################################################
sub check_args {
  GetOptions (
              # required
              "f|file=s" =>  \$glob_files, # only one can be used:
			  "filter|filter_files=s" => \$filter_files, # to filter granulary files with a callback
              "command=s" =>  \$command, # or file or command  see check_config
              "regex_valid_line=s" =>  \$valid_rex,
              "pattern_separator=s" => \$rec_sep,
              "ip_position=i" => \$ip_pos,
              "max|occurences=i"  => \$max_occ, # has a default
              "sleep=i"  => \$wait,        # has a default
              "block|block_rule=s" => \$block_rule,
              "unblock|unblock_rule=s" => \$unblock_rule,
              # optionals
              "discount=i" => \$discount,
              "time_of_block=i" =>  \$block_dur,
              "log=s" => \$log_file,
              "execute|X" =>   \$effectively_run,
              "whitelist=s" => \@wlist,

              "garbage"  => \$garbage,
              "verbosity=i" => \$verbosity,
              "help|?"  => \$help,
              # f c r p i m|o s b u d t l e|X w g v h
              ) or pod2usage("ERROR parsing command line\n");

	if ($help > 0){pod2usage(-verbose => 2,-message => "\nHelp for $0:\n")}
	if ($glob_files && $command){
		die "ERROR --file and --command cannot coexists";
	}
	if ( $filter_files ){
		local $@;
		my $code = eval $filter_files;
		if($@){
			print "ERROR code passed (-->$filter_files<--) does not compile!\n$@\n";
			exit 1;
		}
		else{
				$filter_files_string = $filter_files;
				$filter_files = $code;			
		}
	}
	else {$filter_files = sub{1}; $filter_files_string = 'sub{1}' }
}
################################################################################
sub check_config{
#no warnings 'uninitialized';

    unless (  ($glob_files or $command) && (ref $valid_rex eq 'Regexp') &&
              (ref $rec_sep eq 'Regexp') && (defined $ip_pos) &&
              ($max_occ > 1) && ($wait > 1) ) {
#no warnings 'uninitialized';
          biprint ("\nERROR arguments required:\n".
          "--file or --command --regex_valid_line --pattern_separator --ip_position --max --sleep --block_rule --unblock_rule\n\n".
          "--max and --sleep have some default, other must be specified in command line.\n\n".
          (sprintf '%-20s',"--file").($glob_files ? "glob $glob_files":'')."\n".
		  (sprintf '%-20s',"--filter_files")."$filter_files_string\n".
		  (sprintf '%-20s',"--command").($command ? $command : '')."\n".
          (sprintf '%-20s',"--regex_valid_line")."$valid_rex\n".
          (sprintf '%-20s',"--pattern_separator")."$rec_sep\n".
          (sprintf '%-20s',"--ip_position")."$ip_pos\n".
          (sprintf '%-20s',"--max")."$max_occ\n".
          (sprintf '%-20s',"--sleep")."$wait\n".
          (sprintf '%-20s',"--block_rule")."$block_rule\n".
          (sprintf '%-20s',"--unblock_rule")."$unblock_rule\n"
          );
          die "\nnot enought information to run $0";
          }
          if ($command) {
              biprint("WARNING command processing experimental!");
              #open $cmd_handle,"$command|" or die "ERROR opening [$command]!";
              # create the entry in visited_file cache
              #$visited_files{$command}=[0,0];
          }
		  
}
################################################################################
sub tell_files {
	unless (scalar @_){
				print "No file to process\n" if  $verbosity > 0;
	}
  foreach my $file (@_){

      unless (-e $file){
          biprint ("WARNING $file not found\n");
          next;
      }
      my $mtime = (stat $file)[9];
      my $read_pointer = 0;
      # file updated are read only from certain line
      if (exists $visited_files{$file} and $visited_files{$file}[0] < $mtime ){
          biprint ("processing a modified $file from line ".
                ($visited_files{$file}[1]|| 0).
                "(last modified: ".scalar localtime($mtime).")\n") if $verbosity > 0;
          $read_pointer = $visited_files{$file}[1];
      }
	  # v18 modification for win32 files where timestamp is NOT updated correctly
      elsif(exists $visited_files{$file} and $^O eq 'MSWin32'){
			biprint ("processing anyway (MSWin32) $file from line ".
                ($visited_files{$file}[1]|| 0).
                "(last modified: ".scalar localtime($mtime).")\n") if $verbosity > 0;
          $read_pointer = $visited_files{$file}[1];
	  }
	  # END v18 modification for win32 files where timestamp is NOT updated correctly
      #file not updated are skipped
      elsif (exists $visited_files{$file} and $visited_files{$file}[0] >= $mtime ){
          biprint ("skipping $file because was not modified from last scan(".
                scalar localtime($visited_files{$file}[0]).")\n") if $verbosity > 1; #v17 was > 0
          next;
      }
      # new files
      else {
           biprint ("processing new file $file\n") if $verbosity > 0;
      }
      # mark the file as visited and note the time of last modification
      $visited_files{$file}[0] = $mtime;
      # process the file eventually from a given line
      &proc_file($file,$read_pointer);
  }
}
################################################################################
sub proc_file{
  my $file = shift;
  my $first_line = shift || 0;
  my $proc_lines = 0;
  open my $fh,'<',$file or die "unable to open $file for reading!";
  while (<$fh>){
      next unless $. > $first_line;
      $proc_lines++;
      proc_line($file,$.,$_);
  }
  biprint ("$proc_lines lines processed from $file\n\n")if $verbosity > 1;
  $visited_files{$file}[0] = time;
  $visited_files{$file}[1] = $. if eof;
  close $fh;
}
################################################################################
sub proc_command{
	die "parsing command output still unimplemented..";
  open $cmd_handle,"$command|" or die "ERROR opening [$command]!";
  my $proc_lines = 0;
  while (<$cmd_handle>){
      $proc_lines++;
      proc_line($command,$.,$_);
  }
  biprint ("$proc_lines lines processed from [$command]\n\n")if $verbosity > 1;
  close $cmd_handle;
}
################################################################################
sub proc_line{
      my ($source,$line_num,$line) = @_;
      chomp $line;
      unless ($line =~ /$valid_rex/) {
              print $garb "$source:$line_num $line\n" if $garbage;
              return 0;
      }
      my @parts = split $rec_sep,$line;
      $parts[$ip_pos] =~/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;
      if (defined $1 && defined $2 && defined $3 && defined $4){
            my $sure_ip = "$1.$2.$3.$4";
            if (exists $white_list{$sure_ip}) {
                print $garb "$source:$line_num WHITELIST $line\n" if $garbage;
                return 0;
            }
            else {
               print $garb "\t\tVALID LINE:$source:$line_num $line\n" if $garbage;
            }
            $ip{$sure_ip}++;
            $ip_count{$sure_ip}++ if ($verbosity > 2 and exists $ip_count{$sure_ip});
            #return $sure_ip;
      }
      else {
            biprint ( "\n\nERROR spotting IP at position $ip_pos ".
                      "(review your regexes and position parameters)\n");
            biprint("DEBUG current line:\n\t[$line]\n");
            biprint ("DEBUG ".($#parts-1)." parts (0-$#parts) found at $source line $line_num:\n");
            biprint (map{($_==$ip_pos ?"your choice\t":"\t\t")."$_\t[$parts[$_]]\n"} 0..$#parts);
            biprint ("ERROR specified position $ip_pos is out of range\n")
                    if $ip_pos > $#parts;
            biprint ("\nEXITING after clean up\n");
            &clean_up;
      }
}
################################################################################
sub enq_jobs {
    foreach my $ip (reverse sort { $ip{$a} <=> $ip{$b}}
                    grep {$ip{$_} >= $max_occ} keys %ip){
        biprint ("$ip\t$ip{$ip} occurrences\n") if $verbosity > 0;
        if (exists $job{$ip.'_UNBLOCK'} and ! exists $job{$ip.'_BLOCK'}){

            $job{$ip.'_UNBLOCK'} += $block_dur;
            biprint ( "$ip\talready blocked: ".
                  "+$block_dur seconds to unblock time ".
                  "(now scheduled for: ".
                  scalar localtime($job{$ip.'_UNBLOCK'}).")\n")if $verbosity > 0;
        }
        elsif (exists $job{$ip.'_UNBLOCK'} and  exists $job{$ip.'_BLOCK'}){
            biprint ("WARNING: both block and unblock jobs yet defined: skipping\n");
        }
        elsif (! exists $job{$ip.'_UNBLOCK'} and  exists $job{$ip.'_BLOCK'}){
            biprint ("ERROR: block defined but unblock not found! ".
                  "The program will die. Review your firewall rules\n");
            die;
        }
        else{
            $job{$ip.'_BLOCK'}   = time; #was 0!!
            $job{$ip.'_UNBLOCK'} = time + $block_dur;
            biprint ("$ip\thas now BLOCK and UNBLOCK jobs\n") if $verbosity > 1;
            if ($verbosity > 2){
                $ip_count{$ip} = $ip{$ip};
            }
        }
        # apply the discount
        $ip{$ip} -= $discount;
        if ($ip{$ip} < 1) {
            biprint ("$ip\tremoved from IP cache (less than 1 occurence after discount)\n\n") if $verbosity > 1;
            delete $ip{$ip};
        }
        else {
              biprint ("$ip\toccurences lowered by $discount (now $ip{$ip})\n\n")if $verbosity > 1;
        }
    }

}
################################################################################
sub exec_jobs {
    foreach my $task ( sort { $job{$a} <=> $job{$b}} keys %job){
          # skip future jobs
          next unless $job{$task} <= time;
          # 1.1.1.1_BLOCK => seconds from epoch
          my ($ip, $type) = split /_/, $task;
          # tell block from unblock
          my $system = $type eq 'BLOCK' ? $block_rule : $unblock_rule ;
          # interpolate ip and rulename ( rulename used in MSWin32)
          $system =~ s/_IP_/$ip/g;
          $system =~ s/_NAME_/${ip}_BLOCK/g;

          unless ($effectively_run){
              biprint ("DRY RUN\t$system\n");
              # remove the job from queue even if dry run
              delete $job{$task};
              next;
          }
          biprint (scalar localtime(time),"\nEXECUTING\t$system\n");
          system($system);
          if ($? == 0) {
                biprint ("OK command executed succesfully\n");
                # remove the job from queue
                delete $job{$task};
                next;
          }
          elsif ($? == -1) {
                biprint ("ERROR: failed to execute: $!\n");
          }
          elsif ($? & 127) {
                biprint (sprintf "ERROR: child died with signal %d, %s coredump\n",
                ($? & 127),  ($? & 128) ? 'with' : 'without');
          }
          else {
                biprint (sprintf "child exited with value %d\n", $? >> 8);
          }
    }
}
################################################################################
sub biprint{
    print $output @_;
    print STDOUT @_;
}
################################################################################
sub show_config{
      return "$0 running on $^O at ".scalar(localtime(time))."\n".
      "current configuration:\n\n".
      (sprintf '%-35s',"-f files to read").($glob_files ? "glob $glob_files":'')."\n".
	  (sprintf '%-35s',"-filter_files")."$filter_files_string\n".		  
      (sprintf '%-35s',"-c command").($command ? $command : '')."\n".
      (sprintf '%-35s',"-r regex of valid lines")."$valid_rex\n".
      (sprintf '%-35s',"-p regex to split valid lines")."$rec_sep\n".
      (sprintf '%-35s',"-i position of remote IP from zero")."$ip_pos\n".
      (sprintf '%-35s',"-m max allowed occurences of IP")."$max_occ\n".
      (sprintf '%-35s',"-s wait time between runs")."$wait\n".
      (sprintf '%-35s',"-d discount applied after a block")."$discount\n".
      (sprintf '%-35s',"-t duration of block")."$block_dur\n".
      (sprintf '%-35s',"-b block template")."$block_rule\n".
      (sprintf '%-35s',"-u unblock template")."$unblock_rule\n".
      (sprintf '%-35s',"-l logfile")."$log_file\n".
      (sprintf '%-35s',"-w whitelist")."@wlist\n".
      (sprintf '%-35s',"-g garbage")."$garbage\n".
      (sprintf '%-35s',"-v verbosity")."$verbosity\n".
      (sprintf '%-35s',"-X execution mode").($effectively_run ? 'RUN' : 'DRY RUN')."\n".
      "\n";
}
################################################################################
sub clean_up {
    if ($effectively_run == 0){
        biprint ("OK Nothing to clean on a DRY RUN\n");
		close $cmd_handle if $cmd_handle;
        exit;
    }
    biprint("WARNING $0 was ask to terminate and will try to remove all applied rules\n");
    map {$job{$_} = 0} keys %job;
    exec_jobs;
    biprint ("\n".(scalar keys %job)." jobs pending:\n");
    biprint (map {"$_ ".scalar localtime($job{$_})."\n"} sort { $job{$a} <=> $job{$b}} keys %job);
    biprint ("ERROR ".(scalar keys %job)."jobs still pending! review your firewall!\n") if scalar keys %job;
	close $cmd_handle if $cmd_handle;
    exit;
}
__DATA__

=head1 NAME

 log2fire.pl

=head1 SYNOPSIS

 log2fire.pl

  REQUIRED ARGUMENTS
 
   -f --file  str
              required string with a filename or a glob to be expanded. Every
              file in the list is searched. Modified files are reread only from
              last visited line. Glob is expanded each iteration to take in count
              newly created files
              
   -r --regex_valid_line str
              is the regex to validate every line read from log.
              Lines that does not match this regex are skipped

   -p --pattern_separator str
              this required regex is used to split a valid line into fields

   -i --ip_position  int
              is the position, starting from zro, where remote IPs are found.
              IPs are cleaned from unnecessary charaters automatically

   -m --max or -o --occurences  int
              when one IP reaches this value, a pair of jobs (block
              and unblock one) are enqueued. Default to 50

   -s --sleep [int]
              the program check for new entry in files and execute his block and
              unblock jobs waiting the amount of time specified with this option.
              Default value 5

   -b --block_rule str
              the template of the block rule to be executed. when block and
              unblock rule are to be applied the special entry _IP_ is substitued
              with the actual remote IP and _NAME_ is interpolated in the rule
              name itself (only used in Win32 systems)

   -u --unblock_rule str
              the templete for the unblock rule. Same interpolation of the
              block rule


   OPTIONAL ARGUMENTS
   
   -filter --filter_files code string
			  pass a string containing an anonymous sub to filter files globbed.
			  The sub must return 1 if the the current file is to be processed and
              0 otherwise. This can be used to just process the today logfile.			
   
   -d --discount int
              after reaching the --max number of occurences and after having been
              blocked an IP get a discount in term of numbers of occurences.
              this discount default to the same value of --max

   -t --time_of_block int
              the duration in second of the block. Default 300

   -l --log   str
              the name of the log written by this program. Default to the program
              name with .log appended

   -e --execute -X
              unless specified the program will run on a dry run without
              executing any system call at all

   -w --whitelist str
              can be used more times. IPs in this list are skipped
   
   -g --garbage
              whit this switch all lines processed are printed, distinguishing valid
              ones from unvalid ones, to a separate file for debugging purpose.
              This file has the same name of the log with a .garbage appended
   
   -v --verbosity int
              the level of verbosity from 0, default, to 3

   -h --help
              shows this text
   

=head1 EXAMPLES

A Linux example, made multiline for readability, running against a vstpd.log file
of the format

C<Mon Aug 21 14:33:24 2006 [pid 20175] [dcid] FAIL LOGIN: Client "1.2.3.4">

  log2fire.pl -file vstpd.log
              -pattern_separator \s
              -regex 'FAIL LOGIN: Client'
              -max 50
              -sleep 5
              -ip_position 11
              -block_rule 'iptables -A INPUT -s _IP_ -j DROP'
              -unblock_rule 'iptables -D INPUT -s _IP_ -j DROP'

              -verbosity 0

The extracted IP is conveniently cleaned from C<"1.2.3.4"> to C<1.2.3.4>
Another option in this case could be to use C<-separator "> and C<-position 1>.

A Win32 example against an FTP log of the format:

C<01:23:04 123.123.123.123 - MSFTPSVC1 FTPSRV 3.3.3.3 21 [697]PASS anonymous - 530 1326 0 0 0 FTP - - - ->

  log2fire.pl -file *.log
              -pattern_separator \s
              -regex "PASS\s[^\d]+\s-\s530"
              -max 50
              -sleep 5
              -ip_position 1
              -verbosity 3
              -block_rule "netsh advfirewall firewall add rule name=_NAME_ dir=in action=block protocol=TCP localport=21 remoteip=_IP_"
              -unblock_rule "netsh advfirewall firewall delete rule name=_NAME_"

A Win32 tricky and probably not wise example where the log examinated is the output of a
C<netstat -n 3> command (C<TCP    1.1.1.1:3389   123.223.233.234:3122    ESTABLISHED>)


  log2fire.pl -file netstat-n3-output.log
              -patter_separator \s+
              -regex "\d:3389\s"
              -max 2
              -sleep 5
              -ip_position 2
              -verbosity 3
              -block_rule "netsh advfirewall firewall add rule name=_NAME_ dir=in action=block protocol=TCP localport=3389 remoteip=_IP_"
              -unblock_rule "netsh advfirewall firewall delete rule name=_NAME_"

              -log blocked-rdp-sessions.log
              -whitelist 2.2.2.2
              -whitelist 2.2.2.3


=head1 DESCRIPTION

The program reads one or more files (C<--file> accepts a glob too), search for valid
lines (validated by C<--regex>), split those lines using C<--pattern_separator> and take only
the IP at the specified C<--ip_position>. IP are then cleaned from all unnecessary
characters like quotes or semicolon. All IP (with the exception of those putted
in the C<--whitelist>) are stored in a cache where number of their occurences are
stored too.

For each IP exceeding the C<--max>, a pair of jobs are scheduled to run. The first is
the block one and is scheduled to run immediatly. The latter is the unblock one
and is scheduled to run after C<--time_of_block>, expressed in seconds.

Block and unblock rules are composed using templates given as arguments, C<--block_rule>
and C<--unblock_rule>. During the composition of the effective command C<_IP_> will be
substituted with the current IP and C<_NAME_> with the rule name of the current
block rule (used only in Win32 to delete rules by name).

If C<--execute> or C<--X> is specified the command is run against the current firewall.
In other cases only a dry run is performed.

After an IP is blocked his occurence value stored in the cache is lowered by the
means of C<--discount>.

If an IP yet blocked is still over C<--max> at the next check, the corresponding
unblock job is posticipated by C<--time_of_block> seconds and C<--discount> is applied.

The program will check every C<--sleep> seconds for unread lines in every
files it was told to look in.

The program will always appends his output to a logfile. The detail found in such
logfile is the same printed on the screen and is controlled by C<--verbosity>.

With the C<--garbage> switch all lines processed are sent to another file (with the same
name of the log on but with .garbage appended) for debugging purpose. This file
will be greater than all you precessed logs and valid lines are indented and marked
explicitly as valid. This switch can be useful to polish regexes used to spot what
you are looking for.

=head1 DISCLAIMER

This program is not a professional firewall solution. The Linux firewall has yet
the possibility to build a statefull firewall very well. This program is inteded
as an experiment and should not be run on production machines. Run it only at your
very own risk. As always.


=head1 BUGS AND LIMITATIONS

On win32 systems only CTRL-C can be safely caugth. So if you kill from something like
the task manager, no cleanup of jobs is done. Probably you'll end with a bad
firewal configuration and you'll need to eliminate manually rules added by this
program. Man advised half safe.

=head1 AUTHOR

Discipulus as found at perlmonks

=cut
