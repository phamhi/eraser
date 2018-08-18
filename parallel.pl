#!/usr/bin/perl -w

# Copyright (C) 2007,2008,2009,2010,2011,2012 Ole Tange and Free Software
# Foundation, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>
# or write to the Free Software Foundation, Inc., 51 Franklin St,
# Fifth Floor, Boston, MA 02110-1301 USA

# open3 used in Job::start
use IPC::Open3;
# &WNOHANG used in reaper
use POSIX qw(:sys_wait_h setsid ceil :errno_h);
# gensym used in Job::start
use Symbol qw(gensym);
# tempfile used in Job::start
use File::Temp qw(tempfile tempdir);
# GetOptions used in get_options_from_array
use Getopt::Long;
# Used to ensure code quality
use strict;

$::oodebug=0;
$SIG{TERM} ||= sub { exit 0; }; # $SIG{TERM} is not set on Mac OS X
if(not $ENV{SHELL}) {
    # $ENV{SHELL} is sometimes not set on Mac OS X and Windows
    ::warning("\$SHELL not set. Using /bin/sh.\n");
    $ENV{SHELL} = "/bin/sh";
}
%Global::original_sig = %SIG;
$SIG{TERM} = sub {}; # Dummy until jobs really start
open $Global::original_stderr, ">&STDERR" or ::die_bug("Can't dup STDERR: $!");

parse_options();
my $number_of_args;
if($Global::max_number_of_args) {
    $number_of_args=$Global::max_number_of_args;
} elsif ($::opt_X or $::opt_m) {
    $number_of_args = undef;
} else {
    $number_of_args = 1;
}

my $command = "";
if(@ARGV) {
    if($Global::quoting) {
	$command = shell_quote(@ARGV);
    } else {
	$command = join(" ", @ARGV);
    }
}

my @fhlist;
@fhlist = map { open_or_exit($_) } @::opt_a;
if(not @fhlist) {
    @fhlist = (*STDIN);
}
if($::opt_skip_first_line) {
    # Skip the first line for the first file handle
    my $fh = $fhlist[0];
    <$fh>;
}
if($::opt_header and not $::opt_pipe) {
    my $fh = $fhlist[0];
    # split with colsep or \t
    # TODO should $header force $colsep = \t if undef?
    my $delimiter = $::opt_colsep;
    my $id = 1;
    for my $fh (@fhlist) {
	my $line = <$fh>;
	chomp($line);
	::debug("Delimiter: '$delimiter'");
	for my $s (split /$delimiter/o, $line) {
	    ::debug("Colname: '$s'");
	    $command =~ s:\{$s(|/|//|\.|/\.)\}:\{$id$1\}:g;
	    $id++;
	}
    }
}

# Parallel check for all hosts are up
if($::opt_filter_hosts) {
    my @S = map { "-S " . ::shell_quote_scalar($_) } @::opt_sshlogin;
    my @slf = map { "--slf " . ::shell_quote_scalar($_) } @::opt_sshloginfile;
    my $cmd = "$0 --tag --joblog - -k --nonall @S @slf " .
	"parallel --number-of-cores \\;".
	"parallel --number-of-cpus \\;".
	"parallel --max-line-length-allowed";
    ::debug($cmd."\n");
    open(HOST, "$cmd |") || ::die_bug("parallel host check: $cmd");
    my (%ncores, %ncpus, %time_to_login, %maxlen);
    while(<HOST>) {
	my @col = split /\t/, $_;
	if(defined $col[6]) {
	    if($col[6] eq "255") {
		# signal == 255: ssh failed
		# Remove sshlogin
		delete $Global::host{$col[1]};
	    } elsif($col[6] eq "127") {
		# signal == 127: parallel not installed remote
		# Set ncpus and ncores = 1
		::warning("Could not figure out ",
			  "number of cpus on $col[1]. Using 1.\n");
		$ncores{$col[1]} = 1;
		$ncpus{$col[1]} = 1;
		$maxlen{$col[1]} = Limits::Command::max_length();
	    } elsif($col[0] eq "1" and $Global::host{$col[1]}) {
		# 1  server  1338156112.05  0.303  0  0  0  0
		# parallel --number-of-cores ; parallel --number-of-cpus
		# Remember how log it took to log in
		$time_to_login{$col[1]} = $col[3];
	    } elsif($col[0] eq "Seq" and $col[1] eq "Host" and
		    $col[2] eq "Starttime" and $col[3] eq "Runtime") {
		# skip
	    } else {
		::die_bug("host check unmatched long jobline : $_");
	    }
	} elsif($Global::host{$col[0]}) {
	    # ncores: server       8
	    # ncpus:  server       2
	    # maxlen: server       131071
	    if(not $ncores{$col[0]}) {
		$ncores{$col[0]} = $col[1];
	    } elsif(not $ncpus{$col[0]}) {
		$ncpus{$col[0]} = $col[1];
	    } elsif(not $maxlen{$col[0]}) {
		$maxlen{$col[0]} = $col[1];
	    } else {
		::die_bug("host check too many col0: $_");
	    }
	} else {
	    ::die_bug("host check unmatched short jobline: $_");
	}
    }
    close HOST;
    while (my ($sshlogin, $obj) = each %Global::host) {
	$ncpus{$sshlogin} or ::die_bug("ncpus missing: ".$obj->serverlogin());
	$ncores{$sshlogin} or ::die_bug("ncores missing: ".$obj->serverlogin());
	$time_to_login{$sshlogin} or ::die_bug("ncores missing: ".$obj->serverlogin());
	$maxlen{$sshlogin} or ::die_bug("maxlen missing: ".$obj->serverlogin());
	if($::opt_use_cpus_instead_of_cores) {
	    $obj->set_ncpus($ncpus{$sshlogin});
	} else {
	    $obj->set_ncpus($ncores{$sshlogin});
	}
	$obj->set_time_to_login($time_to_login{$sshlogin});
	$obj->set_time_to_login($time_to_login{$sshlogin});
        $obj->set_maxlength($maxlen{$sshlogin});
    }
}

if($::opt_nonall or $::opt_onall) {
    # Copy all @fhlist into tempfiles
    my @argfiles = ();
    for my $fh (@fhlist) {
	my ($outfh,$name) = ::tempfile(SUFFIX => ".all");
	print $outfh (<$fh>);
	close $outfh;
	push @argfiles, $name;
    }
    if(@::opt_basefile) { setup_basefile(); }
    # for each sshlogin do:
    # parallel -S $sshlogin $command :::: @argfiles
    #
    # Pass some of the options to the sub-parallels, not all of them as
    # -P should only go to the first, and -S should not be copied at all.
    my $options =
	join(" ",
	     ((defined $::opt_P) ? "-P $::opt_P" : ""),
	     ((defined $::opt_u) ? "-u" : ""),
	     ((defined $::opt_group) ? "-g" : ""),
	     ((defined $::opt_D) ? "-D" : ""),
	);
    my $suboptions =
	join(" ",
	     ((defined $::opt_u) ? "-u" : ""),
	     ((defined $::opt_group) ? "-g" : ""),
	     ((defined $::opt_joblog) ? "--joblog $::opt_joblog" : ""),
	     ((defined $::opt_colsep) ? "--colsep ".shell_quote($::opt_colsep) : ""),
	     ((@::opt_v) ? "-vv" : ""),
	     ((defined $::opt_D) ? "-D" : ""),
	     ((defined $::opt_timeout) ? "--timeout ".$::opt_timeout : ""),
	);
    ::debug("| $0 $options\n");
    open(PARALLEL,"| $0 -j0 $options") ||
	::die_bug("This does not run GNU Parallel: $0 $options");
    for my $sshlogin (values %Global::host) {
	print PARALLEL "$0 $suboptions -j1 ".
	    ((defined $::opt_tag) ?
	     "--tagstring ".shell_quote_scalar($sshlogin->string()) : "").
	     " -S ". shell_quote_scalar($sshlogin->string())." ".
	     shell_quote_scalar($command)." :::: @argfiles\n";
    }
    close PARALLEL;
    $Global::exitstatus = $? >> 8;
    debug("--onall exitvalue ",$?);
    if(@::opt_basefile) { cleanup_basefile(); }
    unlink(@argfiles);
    wait_and_exit(min(undef_as_zero($Global::exitstatus),254));
}

$Global::JobQueue = JobQueue->new(
    $command,\@fhlist,$Global::ContextReplace,$number_of_args,\@Global::ret_files);
if($::opt_eta) {
    # Count the number of jobs before starting any
    $Global::JobQueue->total_jobs();
}
for my $sshlogin (values %Global::host) {
    $sshlogin->max_jobs_running();
}

init_run_jobs();
my $sem;
if($Global::semaphore) {
    $sem = acquire_semaphore();
}
$SIG{TERM} = \&start_no_new_jobs;
start_more_jobs();
if($::opt_pipe) {
    spreadstdin(@fhlist);
}
::debug("Start draining\n");
drain_job_queue();
::debug("Done draining\n");
reaper();
cleanup();
if($Global::semaphore) {
    $sem->release();
}
if($::opt_halt_on_error) {
    wait_and_exit($Global::halt_on_error_exitstatus);
} else {
    wait_and_exit(min(undef_as_zero($Global::exitstatus),254));
}

sub __PIPE_MODE__ {}

sub spreadstdin {
    # read a record
    # Spawn a job and print the record to it.
    my @fhlist = @_; # Filehandles to read from (Defaults to STDIN)
    my $record;
    my $buf = "";
    my $header = "";
    if($::opt_header) {
	my $non_greedy_regexp = $::opt_header;
	# ? , * , + , {} => ?? , *? , +? , {}?
	$non_greedy_regexp =~ s/(\?|\*|\+|\})/$1\?/g;
	while(read(STDIN,substr($buf,length $buf,0),$::opt_blocksize)) {
	    if($buf=~s/^(.*?$non_greedy_regexp)//) {
		$header = $1; last;
	    }
	}
    }
    my ($recstart,$recend,$recerror);
    if(defined($::opt_recstart) and defined($::opt_recend)) {
	# If both --recstart and --recend is given then both must match
	$recstart = $::opt_recstart;
	$recend = $::opt_recend;
	$recerror = "parallel: Warning: --recend and --recstart unmatched. Is --blocksize too small?";
    } elsif(defined($::opt_recstart)) {
	# If --recstart is given it must match start of record
	$recstart = $::opt_recstart;
	$recend = "";
	$recerror = "parallel: Warning: --recstart unmatched. Is --blocksize too small?";
    } elsif(defined($::opt_recend)) {
	# If --recend is given then it must match end of record
	$recstart = "";
	$recend = $::opt_recend;
	$recerror = "parallel: Warning: --recend unmatched. Is --blocksize too small?";
    }

    if($::opt_regexp) {
	# If $recstart/$recend contains '|' this should only apply to the regexp
	$recstart = "(?:".$recstart.")";
	$recend = "(?:".$recend.")";
    } else {
	# $recstart/$recend = printf strings (\n)
	$recstart =~ s/\\([rnt'"\\])/"qq|\\$1|"/gee;
	$recend =~ s/\\([rnt'"\\])/"qq|\\$1|"/gee;
    }
    my $recendrecstart = $recend.$recstart;
    # Force the while-loop once if everything was read by header reading
    my $force_one_time_through = 0;
    for my $in (@fhlist) {
	piperead: while(1) {
	    if(!$force_one_time_through) {
		$force_one_time_through++;
	    } elsif($Global::max_lines) {
		# Read $Global::max_lines lines
		eof($in) and last piperead;
		for(my $t = 0; !eof($in) and
		    substr($buf,length $buf,0) = <$in> and $t < $Global::max_lines;
		    $t++) {}
	    } else {
		# Read a block
		read($in,substr($buf,length $buf,0),$::opt_blocksize) or last;
		# substr above = append to $buf
	    }
	    if($::opt_r) {
		# Remove empty lines
		$buf=~s/^\s*\n//gm;
		if(length $buf == 0) {
		    next;
		}
	    }
	    if($::opt_regexp) {
		if($Global::max_number_of_args) {
		    # -N => (start..*?end){n}
		    while($buf =~ s/((?:$recstart.*?$recend){$Global::max_number_of_args})($recstart.*)$/$2/os) {
			write_record_to_pipe(\$header,\$1,$recstart,$recend,length $1);
		    }
		} else {
		    # Find the last recend-recstart in $buf
		    if($buf =~ s/(.*$recend)($recstart.*?)$/$2/os) {
			write_record_to_pipe(\$header,\$1,$recstart,$recend,length $1);
		    }
		}
	    } else {
		if($Global::max_number_of_args) {
		    # -N => (start..*?end){n}
		    my $i = 0;
		    while(($i = nindex(\$buf,$recendrecstart,$Global::max_number_of_args)) != -1) {
			$i += length $recend; # find the actual splitting location
			write_record_to_pipe(\$header,\$buf,$recstart,$recend,$i);
			substr($buf,0,$i) = "";
		    }
		} else {
		    # Find the last recend-recstart in $buf
		    my $i = rindex($buf,$recendrecstart);
		    if($i != -1) {
			$i += length $recend; # find the actual splitting location
			write_record_to_pipe(\$header,\$buf,$recstart,$recend,$i);
			substr($buf,0,$i) = "";
		    }
		}
	    }
	}
    }

    # If there is anything left in the buffer write it
    substr($buf,0,0) = "";
    write_record_to_pipe(\$header,\$buf,$recstart,$recend,length $buf);

    ::debug("Done reading input\n");
    $Global::start_no_new_jobs = 1;
}

sub nindex {
    # See if string is in buffer N times
    # Returns:
    #   the position where the Nth copy is found
    my $buf_ref = shift;
    my $str = shift;
    my $n = shift;
    my $i = 0;
    for(1..$n) {
	$i = index($$buf_ref,$str,$i+1);
	if($i == -1) { last }
    }
    return $i;
}

sub write_record_to_pipe {
    # Fork then
    # Write record from pos 0 .. $endpos to pipe
    my $header_ref = shift;
    my $record_ref = shift;
    my $recstart = shift;
    my $recend = shift;
    my $endpos = shift;
    if(length $$record_ref == 0) { return; }
    # Find the minimal seq $job that has no data written == virgin
    # If no virgin found, backoff
    my $sleep = 0.0001; # 0.01 ms - better performance on highend
    while(not @Global::virgin_jobs) {
	::debug("No virgin jobs");
	$sleep = ::reap_usleep($sleep);
	start_more_jobs(); # These jobs may not be started because of loadavg
    }
    my $job = shift @Global::virgin_jobs;
    if(fork()) {
	# Skip
    } else {
	# Chop of at $endpos as we do not know how many rec_sep will
	# be removed.
	my $record = substr($$record_ref,0,$endpos);
	# Remove rec_sep
	if($::opt_remove_rec_sep) {
	    # Remove record separator
	    $record =~ s/$recend$recstart//gos;
	    $record =~ s/^$recstart//os;
	    $record =~ s/$recend$//os;
	}
	$job->write($header_ref);
	$job->write(\$record);
	my $fh = $job->stdin();
	close $fh;
	exit(0);
    }
    my $fh = $job->stdin();
    close $fh;
    return;
}

sub __SEM_MODE__ {}

sub acquire_semaphore {
    # Acquires semaphore. If needed: spawns to the background
    # Returns:
    #   The semaphore to be released when jobs is complete
    $Global::host{':'} = SSHLogin->new(":");
    my $sem = Semaphore->new($Semaphore::name,$Global::host{':'}->max_jobs_running());
    $sem->acquire();
    debug("run");
    if($Semaphore::fg) {
	# skip
    } else {
	# If run in the background, the PID will change
	# therefore release and re-acquire the semaphore
	$sem->release();
	if(fork()) {
	    exit(0);
	} else {
	    # child
	    # Get a semaphore for this pid
	    ::die_bug("Can't start a new session: $!") if setsid() == -1;
	    $sem = Semaphore->new($Semaphore::name,$Global::host{':'}->max_jobs_running());
	    $sem->acquire();
	}
    }
    return $sem;
}

sub __PARSE_OPTIONS__ {}

sub options_hash {
    # Returns a hash of the GetOptions config
    return
	("debug|D" => \$::opt_D,
	 "xargs" => \$::opt_xargs,
	 "m" => \$::opt_m,
	 "X" => \$::opt_X,
	 "v" => \@::opt_v,
	 "joblog=s" => \$::opt_joblog,
	 "resume" => \$::opt_resume,
	 "silent" => \$::opt_silent,
	 #"silent-error|silenterror" => \$::opt_silent_error,
	 "keep-order|keeporder|k" => \$::opt_k,
	 "group" => \$::opt_group,
	 "g" => \$::opt_retired,
	 "ungroup|u" => \$::opt_u,
	 "null|0" => \$::opt_0,
	 "quote|q" => \$::opt_q,
	 "I=s" => \$::opt_I,
	 "extensionreplace|er=s" => \$::opt_U,
	 "U=s" => \$::opt_retired,
	 "basenamereplace|bnr=s" => \$::opt_basenamereplace,
	 "dirnamereplace|dnr=s" => \$::opt_dirnamereplace,
	 "basenameextensionreplace|bner=s" => \$::opt_basenameextensionreplace,
	 "seqreplace=s" => \$::opt_seqreplace,
	 "jobs|j=s" => \$::opt_P,
	 "load=s" => \$::opt_load,
	 "noswap" => \$::opt_noswap,
	 "max-line-length-allowed" => \$::opt_max_line_length_allowed,
	 "number-of-cpus" => \$::opt_number_of_cpus,
	 "number-of-cores" => \$::opt_number_of_cores,
	 "use-cpus-instead-of-cores" => \$::opt_use_cpus_instead_of_cores,
	 "shellquote|shell_quote|shell-quote" => \$::opt_shellquote,
	 "nice=i" => \$::opt_nice,
	 "timeout=i" => \$::opt_timeout,
	 "tag" => \$::opt_tag,
	 "tagstring=s" => \$::opt_tagstring,
	 "onall" => \$::opt_onall,
	 "nonall" => \$::opt_nonall,
	 "filter-hosts|filterhosts|filter-host" => \$::opt_filter_hosts,
	 "sshlogin|S=s" => \@::opt_sshlogin,
	 "sshloginfile|slf=s" => \@::opt_sshloginfile,
	 "controlmaster|M" => \$::opt_controlmaster,
	 "return=s" => \@::opt_return,
	 "trc=s" => \@::opt_trc,
	 "transfer" => \$::opt_transfer,
	 "cleanup" => \$::opt_cleanup,
	 "basefile|bf=s" => \@::opt_basefile,
	 "B=s" => \$::opt_retired,
	 "workdir|wd=s" => \$::opt_workdir,
	 "W=s" => \$::opt_retired,
	 "tmpdir=s" => \$::opt_tmpdir,
	 "tempdir=s" => \$::opt_tmpdir,
	 "tty" => \$::opt_tty,
	 "T" => \$::opt_retired,
	 "halt-on-error|halt=i" => \$::opt_halt_on_error,
	 "H=i" => \$::opt_retired,
	 "retries=i" => \$::opt_retries,
	 "dry-run|dryrun" => \$::opt_dryrun,
	 "progress" => \$::opt_progress,
	 "eta" => \$::opt_eta,
	 "arg-sep|argsep=s" => \$::opt_arg_sep,
	 "arg-file-sep|argfilesep=s" => \$::opt_arg_file_sep,
	 "trim=s" => \$::opt_trim,
	 "plain" => \$::opt_plain,
	 "profile|J=s" => \@::opt_profile,
	 "pipe|spreadstdin" => \$::opt_pipe,
	 "recstart=s" => \$::opt_recstart,
	 "recend=s" => \$::opt_recend,
	 "regexp|regex" => \$::opt_regexp,
	 "remove-rec-sep|removerecsep|rrs" => \$::opt_remove_rec_sep,
	 "files|output-as-files|outputasfiles" => \$::opt_files,
	 "block|block-size|blocksize=s" => \$::opt_blocksize,
	 "tollef" => \$::opt_tollef,
	 "gnu" => \$::opt_gnu,
	 "xapply" => \$::opt_xapply,
	 "bibtex" => \$::opt_bibtex,
	 # xargs-compatibility - implemented, man, testsuite
	 "max-procs|P=s" => \$::opt_P,
	 "delimiter|d=s" => \$::opt_d,
	 "max-chars|s=i" => \$::opt_s,
	 "arg-file|a=s" => \@::opt_a,
	 "no-run-if-empty|r" => \$::opt_r,
	 "replace|i:s" => \$::opt_i,
	 "E=s" => \$::opt_E,
	 "eof|e:s" => \$::opt_E,
	 "max-args|n=i" => \$::opt_n,
	 "max-replace-args|N=i" => \$::opt_N,
	 "colsep|col-sep|C=s" => \$::opt_colsep,
	 "help|h" => \$::opt_help,
	 "L=f" => \$::opt_L,
	 "max-lines|l:f" => \$::opt_l,
	 "interactive|p" => \$::opt_p,
	 "verbose|t" => \$::opt_verbose,
	 "version|V" => \$::opt_version,
	 "minversion|min-version=i" => \$::opt_minversion,
	 "show-limits|showlimits" => \$::opt_show_limits,
	 "exit|x" => \$::opt_x,
	 # Semaphore
	 "semaphore" => \$::opt_semaphore,
	 "semaphoretimeout=i" => \$::opt_semaphoretimeout,
	 "semaphorename|id=s" => \$::opt_semaphorename,
	 "fg" => \$::opt_fg,
	 "bg" => \$::opt_bg,
	 "wait" => \$::opt_wait,
	 # Shebang #!/usr/bin/parallel --shebang
	 "shebang|hashbang" => \$::opt_shebang,
	 "Y" => \$::opt_retired,
         "skip-first-line" => \$::opt_skip_first_line,
	 "header=s" => \$::opt_header,
	);
}

sub get_options_from_array {
    # Run GetOptions on @array
    # Returns:
    #   true if parsing worked
    #   false if parsing failed
    #   @array is changed
    my $array_ref = shift;
    # A bit of shuffling of @ARGV needed as GetOptionsFromArray is not
    # supported everywhere
    my @save_argv;
    my $this_is_ARGV = (\@::ARGV == $array_ref);
    if(not $this_is_ARGV) {
	@save_argv = @::ARGV;
	@::ARGV = @{$array_ref};
    }
    my @retval = GetOptions(options_hash());
    if(not $this_is_ARGV) {
	@{$array_ref} = @::ARGV;
	@::ARGV = @save_argv;
    }
    return @retval;
}

sub parse_options {
    # Returns: N/A
    # Defaults:
    $Global::version = 20120822;
    $Global::progname = 'parallel';
    $Global::infinity = 2**31;
    $Global::debug = 0;
    $Global::verbose = 0;
    $Global::grouped = 1;
    $Global::keeporder = 0;
    $Global::quoting = 0;
    $Global::replace{'{}'} = '{}';
    $Global::replace{'{.}'} = '{.}';
    $Global::replace{'{/}'} = '{/}';
    $Global::replace{'{//}'} = '{//}';
    $Global::replace{'{/.}'} = '{/.}';
    $Global::replace{'{#}'} = '{#}';
    $/="\n";
    $Global::ignore_empty = 0;
    $Global::interactive = 0;
    $Global::stderr_verbose = 0;
    $Global::default_simultaneous_sshlogins = 9;
    $Global::exitstatus = 0;
    $Global::halt_on_error_exitstatus = 0;
    $Global::arg_sep = ":::";
    $Global::arg_file_sep = "::::";
    $Global::trim = 'n';
    $Global::max_jobs_running = 0;
    $Global::job_already_run = '';

    @ARGV=read_options();

    if(defined $::opt_retired) {
	    ::error("-g has been retired. Use --group.\n");
	    ::error("-B has been retired. Use --bf.\n");
	    ::error("-T has been retired. Use --tty.\n");
	    ::error("-U has been retired. Use --er.\n");
	    ::error("-W has been retired. Use --wd.\n");
	    ::error("-Y has been retired. Use --shebang.\n");
	    ::error("-H has been retired. Use --halt.\n");
            ::wait_and_exit(255);
    }
    if(@::opt_v) { $Global::verbose = $#::opt_v+1; } # Convert -v -v to v=2
    $Global::debug = (defined $::opt_D);
    if(defined $::opt_X) { $Global::ContextReplace = 1; }
    if(defined $::opt_silent) { $Global::verbose = 0; }
    if(defined $::opt_k) { $Global::keeporder = 1; }
    if(defined $::opt_group) { $Global::grouped = 1; }
    if(defined $::opt_u) { $Global::grouped = 0; }
    if(defined $::opt_0) { $/ = "\0"; }
    if(defined $::opt_d) { my $e="sprintf \"$::opt_d\""; $/ = eval $e; }
    if(defined $::opt_p) { $Global::interactive = $::opt_p; }
    if(defined $::opt_q) { $Global::quoting = 1; }
    if(defined $::opt_r) { $Global::ignore_empty = 1; }
    if(defined $::opt_verbose) { $Global::stderr_verbose = 1; }
    if(defined $::opt_I) { $Global::replace{'{}'} = $::opt_I; }
    if(defined $::opt_U) { $Global::replace{'{.}'} = $::opt_U; }
    if(defined $::opt_i) {
	$Global::replace{'{}'} = $::opt_i eq "" ? "{}" : $::opt_i;
    }
    if(defined $::opt_basenamereplace) { $Global::replace{'{/}'} = $::opt_basenamereplace; }
    if(defined $::opt_dirnamereplace) { $Global::replace{'{//}'} = $::opt_dirnamereplace; }
    if(defined $::opt_basenameextensionreplace) {
        $Global::replace{'{/.}'} = $::opt_basenameextensionreplace;
    }
    if(defined $::opt_seqreplace) {
        $Global::replace{'{#}'} = $::opt_seqreplace;
    }
    if(defined $::opt_E) { $Global::end_of_file_string = $::opt_E; }
    if(defined $::opt_n) { $Global::max_number_of_args = $::opt_n; }
    if(defined $::opt_timeout) { $Global::timeoutq = TimeoutQueue->new($::opt_timeout); }
    if(defined $::opt_tmpdir) { $ENV{'TMPDIR'} = $::opt_tmpdir; }
    if(defined $::opt_help) { die_usage(); }
    if(defined $::opt_colsep) { $Global::trim = 'lr'; }
    if(defined $::opt_header) { $::opt_colsep = defined $::opt_colsep ? $::opt_colsep : "\t"; }
    if(defined $::opt_trim) { $Global::trim = $::opt_trim; }
    if(defined $::opt_arg_sep) { $Global::arg_sep = $::opt_arg_sep; }
    if(defined $::opt_arg_file_sep) { $Global::arg_file_sep = $::opt_arg_file_sep; }
    if(defined $::opt_number_of_cpus) { print SSHLogin::no_of_cpus(),"\n"; wait_and_exit(0); }
    if(defined $::opt_number_of_cores) {
        print SSHLogin::no_of_cores(),"\n"; wait_and_exit(0);
    }
    if(defined $::opt_max_line_length_allowed) {
        print Limits::Command::real_max_length(),"\n"; wait_and_exit(0);
    }
    if(defined $::opt_version) { version(); wait_and_exit(0); }
    if(defined $::opt_bibtex) { bibtex(); wait_and_exit(0); }
    if(defined $::opt_show_limits) { show_limits(); }
    if(@::opt_sshlogin) { @Global::sshlogin = @::opt_sshlogin; }
    if(@::opt_sshloginfile) { read_sshloginfiles(@::opt_sshloginfile); }
    if(@::opt_return) { push @Global::ret_files, @::opt_return; }
    if(not defined $::opt_recstart and
       not defined $::opt_recend) { $::opt_recend = "\n"; }
    if(not defined $::opt_blocksize) { $::opt_blocksize = "1M"; }
    $::opt_blocksize = multiply_binary_prefix($::opt_blocksize);
    if(defined $::opt_semaphore) { $Global::semaphore = 1; }
    if(defined $::opt_semaphoretimeout) { $Global::semaphore = 1; }
    if(defined $::opt_semaphorename) { $Global::semaphore = 1; }
    if(defined $::opt_fg) { $Global::semaphore = 1; }
    if(defined $::opt_bg) { $Global::semaphore = 1; }
    if(defined $::opt_wait) { $Global::semaphore = 1; }
    if(defined $::opt_minversion) {
	print $Global::version,"\n";
	if($Global::version < $::opt_minversion) {
	    wait_and_exit(255);
	} else {
	    wait_and_exit(0);
	}
    }
    if($::opt_tollef and not $::opt_gnu and not $::opt_plain) {
	# Behave like tollef parallel (from moreutils)
	$::opt_u = 1;
	$Global::grouped = 0;
	$Global::quoting = 1;
	$::opt_q = 1;
	if(defined $::opt_l) {
	    $::opt_load = $::opt_l;
	    $::opt_l = undef;
	}
	if(not defined $::opt_arg_sep) {
	    $Global::arg_sep = "--";
	}
	if(not grep(/$Global::arg_sep/, @ARGV)) {
	    unshift(@ARGV, $ENV{SHELL}, "-c", "--");
	}
    }

    if(defined $::opt_nonall) {
	# Append a dummy empty argument
	push @ARGV, $Global::arg_sep, "";
    }
    if(defined $::opt_tty) {
        # Defaults for --tty: -j1 -u
        # Can be overridden with -jXXX -g
        if(not defined $::opt_P) {
            $::opt_P = 1;
        }
        if(not defined $::opt_group) {
            $Global::grouped = 0;
        }
    }
    if(@::opt_trc) {
        push @Global::ret_files, @::opt_trc;
        $::opt_transfer = 1;
        $::opt_cleanup = 1;
    }
    if(defined $::opt_l) {
	if($::opt_l eq "-0") {
	    # -l -0 (swallowed -0)
	    $::opt_l = 1;
	    $::opt_0 = 1;
	    $/ = "\0";
	} elsif ($::opt_l == 0) {
	    # If not given (or if 0 is given) => 1
	    $::opt_l = 1;
	}
	$Global::max_lines = $::opt_l;
	$Global::max_number_of_args ||= $Global::max_lines;
    }

    # Read more than one arg at a time (-L, -N)
    if(defined $::opt_L) {
	$Global::max_lines = $::opt_L;
	$Global::max_number_of_args ||= $Global::max_lines;
    }
    if(defined $::opt_N) {
	$Global::max_number_of_args = $::opt_N;
	$Global::ContextReplace = 1;
    }
    if((defined $::opt_L or defined $::opt_N)
       and
       not ($::opt_xargs or $::opt_m)) {
	$Global::ContextReplace = 1;
    }

    for (keys %Global::replace) {
	$Global::replace{$_} = ::maybe_quote($Global::replace{$_});
    }
    %Global::replace_rev = reverse %Global::replace;
    if(defined $::opt_tag and not defined $::opt_tagstring) {
	$::opt_tagstring = $Global::replace{'{}'};
    }

    if(grep /^$Global::arg_sep$|^$Global::arg_file_sep$/o, @ARGV) {
        # Deal with ::: and ::::
        @ARGV=read_args_from_command_line();
    }

    # Semaphore defaults
    # Must be done before computing number of processes and max_line_length
    # because when running as a semaphore GNU Parallel does not read args
    $Global::semaphore ||= ($0 =~ m:(^|/)sem$:); # called as 'sem'
    if($Global::semaphore) {
        # A semaphore does not take input from neither stdin nor file
        @::opt_a = ("/dev/null");
        push(@Global::unget_argv, [Arg->new("")]);
        $Semaphore::timeout = $::opt_semaphoretimeout || 0;
        if(defined $::opt_semaphorename) {
            $Semaphore::name = $::opt_semaphorename;
        } else {
            $Semaphore::name = `tty`;
            chomp $Semaphore::name;
        }
        $Semaphore::fg = $::opt_fg;
        $Semaphore::wait = $::opt_wait;
        $Global::default_simultaneous_sshlogins = 1;
        if(not defined $::opt_P) {
            $::opt_P = 1;
        }
	if($Global::interactive and $::opt_bg) {
	    ::error("Jobs running in the ".
		    "background cannot be interactive.\n");
            ::wait_and_exit(255);
	}
    }
    if(defined $::opt_eta) {
        $::opt_progress = $::opt_eta;
    }

    parse_sshlogin();

    if(remote_hosts() and ($::opt_X or $::opt_m or $::opt_xargs)) {
        # As we do not know the max line length on the remote machine
        # long commands generated by xargs may fail
        # If opt_N is set, it is probably safe
        ::warning("Using -X or -m with --sshlogin may fail.\n");
    }

    if(not defined $::opt_P) {
        $::opt_P = "100%";
    }
    open_joblog();
}

sub open_joblog {
    my $append = 0;
    if($::opt_resume and not $::opt_joblog) {
        ::error("--resume requires --joblog.\n");
	::wait_and_exit(255);
    }
    if($::opt_joblog) {
	if($::opt_resume) {
	    if(open(JOBLOG, $::opt_joblog)) {
		# Read the joblog
		$append = <JOBLOG>; # If there is a header: Open as append later
		while(<JOBLOG>) {
		    if(/^(\d+)/) {
			# This is 30% faster than set_job_already_run($1);
			vec($Global::job_already_run,$1,1) = 1;
		    } else {
			::error("Format of '$::opt_joblog' is wrong.\n");
			::wait_and_exit(255);
		    }
		}
		close JOBLOG;
	    }
	}
	if($append) {
	    # Append to joblog
	    if(not open($Global::joblog,">>$::opt_joblog")) {
		::error("Cannot append to --joblog $::opt_joblog.\n");
		::wait_and_exit(255);
	    }
	} else {
	    # Overwrite the joblog
	    if(not open($Global::joblog,">$::opt_joblog")) {
		::error("Cannot write to --joblog $::opt_joblog.\n");
		::wait_and_exit(255);
	    } else {
		print $Global::joblog
		    join("\t", "Seq", "Host", "Starttime", "Runtime",
			 "Send", "Receive", "Exitval", "Signal", "Command"
		    ). "\n";
	    }
	}
    }
}

sub read_options {
    # Read options from command line, profile and $PARALLEL
    # Returns:
    #   @ARGV without --options
    # This must be done first as this may exec myself
    if(defined $ARGV[0] and ($ARGV[0]=~/^--shebang / or
                             $ARGV[0]=~/^--hashbang /)) {
        # Program is called from #! line in script
        $ARGV[0]=~s/^--shebang *//; # remove --shebang if it is set
        $ARGV[0]=~s/^--hashbang *//; # remove --hashbang if it is set
        my $argfile = shell_quote_scalar(pop @ARGV);
        # exec myself to split $ARGV[0] into separate fields
	exec "$0 --skip-first-line -a $argfile @ARGV";
    }

    Getopt::Long::Configure("bundling","pass_through");
    # Check if there is a --profile to set @::opt_profile
    GetOptions("profile|J=s" => \@::opt_profile,
	       "plain" => \$::opt_plain) || die_usage();
    my @ARGV_profile = ();
    my @ARGV_env = ();
    if(not $::opt_plain) {
	# Add options from .parallel/config and other profiles
	my @config_profiles = (
	    "/etc/parallel/config",
	    $ENV{'HOME'}."/.parallel/config",
	    $ENV{'HOME'}."/.parallelrc");
	my @profiles = @config_profiles;
	if(@::opt_profile) {
	    # --profile overrides default profiles
	    @profiles = ();
	    for my $profile (@::opt_profile) {
		push @profiles, $ENV{'HOME'}."/.parallel/".$profile;
	    }
	}
	for my $profile (@profiles) {
	    if(-r $profile) {
		open (IN, "<", $profile) || ::die_bug("read-profile: $profile");
		while(<IN>) {
		    /^\s*\#/ and next;
		    chomp;
		    push @ARGV_profile, shell_unquote(split/(?<![\\])\s/, $_);
		}
		close IN;
	    } else {
		if(grep /^$profile$/, @config_profiles) {
		    # config file is not required to exist
		} else {
		    ::error("$profile not readable.\n");
		    wait_and_exit(255);
		}
	    }
	}
	# Add options from shell variable $PARALLEL
	if($ENV{'PARALLEL'}) {
	    @ARGV_env = shell_unquote(split/(?<![\\])\s/, $ENV{'PARALLEL'});
	}
    }
    Getopt::Long::Configure("bundling","require_order");
    get_options_from_array(\@ARGV_profile) || die_usage();
    get_options_from_array(\@ARGV_env) || die_usage();
    get_options_from_array(\@ARGV) || die_usage();

    # Prepend non-options to @ARGV (such as commands like 'nice')
    unshift @ARGV, @ARGV_profile, @ARGV_env;
    return @ARGV;
}

sub read_args_from_command_line {
    # Arguments given on the command line after:
    #   ::: ($Global::arg_sep)
    #   :::: ($Global::arg_file_sep)
    # Removes the arguments from @ARGV and:
    # - puts filenames into -a
    # - puts arguments into files and add the files to -a
    # Returns:
    #   @ARGV without ::: and :::: and following args
    # Input: @ARGV = command option ::: arg arg arg :::: argfiles
    my @new_argv = ();
    for(my $arg = shift @ARGV; @ARGV; $arg = shift @ARGV) {
        if($arg eq $Global::arg_sep
	   or
	   $arg eq $Global::arg_file_sep) {
	    my $group = $arg; # This group of arguments is args or argfiles
	    my @group;
	    while(defined ($arg = shift @ARGV)) {
		if($arg eq $Global::arg_sep
		   or
		   $arg eq $Global::arg_file_sep) {
		    # exit while loop if finding new separator
		    last;
		} else {
		    # If not hitting ::: or ::::
		    # Append it to the group
		    push @group, $arg;
		}
	    }
	    if($group eq $Global::arg_sep) {
		# Group of arguments on the command line.
		# Put them into a file.
		# Create argfile
		my ($outfh,$name) = ::tempfile(SUFFIX => ".arg");
		unlink($name);
		# Put args into argfile
		print $outfh map { $_,$/ } @group;
		seek $outfh, 0, 0;
		# Append filehandle to -a
		push @::opt_a, $outfh;
	    } elsif($group eq $Global::arg_file_sep) {
		# Group of file names on the command line.
		# Append args into -a
		push @::opt_a, @group;
	    } else {
		::die_bug("Unknown command line group: $group");
	    }
	    if(defined($arg)) {
		# $arg is ::: or ::::
		redo;
	    } else {
		# $arg is undef -> @ARGV empty
		last;
	    }
	}
	push @new_argv, $arg;
    }
    # Output: @ARGV = command to run with options
    return @new_argv;
}

sub cleanup {
    # Returns: N/A
    if(@::opt_basefile) { cleanup_basefile(); }
}

sub __QUOTING_ARGUMENTS_FOR_SHELL__ {}

sub shell_quote {
    my @strings = (@_);
    for my $a (@strings) {
        $a =~ s/([\002-\011\013-\032\\\#\?\`\(\)\{\}\[\]\*\>\<\~\|\; \"\!\$\&\'])/\\$1/g;
        $a =~ s/[\n]/'\n'/g; # filenames with '\n' is quoted using \'
    }
    return wantarray ? @strings : "@strings";
}

sub shell_quote_scalar {
    # Quote the string so shell will not expand any special chars
    # Returns:
    #   string quoted with \ as needed by the shell
    my $a = shift;
    $a =~ s/([\002-\011\013-\032\\\#\?\`\(\)\{\}\[\]\*\>\<\~\|\; \"\!\$\&\'])/\\$1/g;
    $a =~ s/[\n]/'\n'/g; # filenames with '\n' is quoted using \'
    return $a;
}

sub maybe_quote {
    # If $Global::quoting then quote the string so shell will not expand any special chars
    # Else do not quote
    # Returns:
    #   if $Global::quoting string quoted with \ as needed by the shell
    #   else string unaltered
    if($Global::quoting) {
	return shell_quote_scalar(@_);
    } else {
	return "@_";
    }
}

sub maybe_unquote {
    # If $Global::quoting then unquote the string as shell would
    # Else do not unquote
    # Returns:
    #   if $Global::quoting string unquoted as done by the shell
    #   else string unaltered
    if($Global::quoting) {
	return shell_unquote(@_);
    } else {
	return "@_";
    }
}

sub shell_unquote {
    # Unquote strings from shell_quote
    # Returns:
    #   string with shell quoting removed
    my @strings = (@_);
    my $arg;
    for $arg (@strings) {
        if(not defined $arg) {
            $arg = "";
        }
        $arg =~ s/'\n'/\n/g; # filenames with '\n' is quoted using \'
        $arg =~ s/\\([\002-\011\013-\032])/$1/g;
        $arg =~ s/\\([\#\?\`\(\)\{\}\*\>\<\~\|\; \"\!\$\&\'])/$1/g;
        $arg =~ s/\\\\/\\/g;
    }
    return wantarray ? @strings : "@strings";
}

sub __FILEHANDLES__ {}

sub enough_file_handles {
    # check that we have enough filehandles available for starting
    # another job
    # Returns:
    #   1 if ungrouped (thus not needing extra filehandles)
    #   0 if too few filehandles
    #   1 if enough filehandles
    if($Global::grouped) {
        my %fh;
        my $enough_filehandles = 1;
        # We need a filehandle for STDOUT and STDERR
	# perl uses 7 filehandles for something?
        # open3 uses 2 extra filehandles temporarily
        for my $i (1..8) {
            $enough_filehandles &&= open($fh{$i},"</dev/null");
        }
        for (values %fh) { close $_; }
        return $enough_filehandles;
    } else {
        return 1;
    }
}

sub open_or_exit {
    # Returns:
    #   file handle to read-opened file
    #   exits if file cannot be opened
    my $file = shift;
    if($file eq "-") {
	$Global::stdin_in_opt_a = 1;
	return ($Global::original_stdin || *STDIN);
    }
    if(ref $file eq "GLOB") {
	# This is an open filehandle
	return $file;
    }
    my $fh = gensym;
    if(not open($fh,"<",$file)) {
        ::error("Cannot open input file `$file': No such file or directory.\n");
        wait_and_exit(255);
    }
    return $fh;
}

sub __RUNNING_THE_JOBS_AND_PRINTING_PROGRESS__ {}

# Variable structure:
#
#    $Global::running{$pid} = Pointer to Job-object
#    @Global::virgin_jobs = Pointer to Job-object that have received no input
#    $Global::host{$sshlogin} = Pointer to SSHLogin-object
#    $Global::total_running = total number of running jobs
#    $Global::total_started = total jobs started

sub init_run_jobs {
    # Remember the original STDOUT and STDERR
    # Returns: N/A
    open $Global::original_stdout, ">&STDOUT" or
	::die_bug("Can't dup STDOUT: $!");
    open $Global::original_stderr, ">&STDERR" or
	::die_bug("Can't dup STDERR: $!");
    open $Global::original_stdin, "<&STDIN" or
	::die_bug("Can't dup STDIN: $!");
    $Global::total_running = 0;
    $Global::total_started = 0;
    $Global::tty_taken = 0;
    $SIG{USR1} = \&list_running_jobs;
    $SIG{USR2} = \&toggle_progress;
    if(@::opt_basefile) { setup_basefile(); }
}

sub start_more_jobs {
    # Returns:
    #   number of jobs started
    my $jobs_started = 0;
    if(not $Global::start_no_new_jobs) {
        if($Global::max_procs_file) {
            my $mtime = (stat($Global::max_procs_file))[9];
            if($mtime > $Global::max_procs_file_last_mod) {
                $Global::max_procs_file_last_mod = $mtime;
                for my $sshlogin (values %Global::host) {
                    $sshlogin->set_max_jobs_running(undef);
                }
            }
        }
        if($Global::max_load_file) {
            my $mtime = (stat($Global::max_load_file))[9];
            if($mtime > $Global::max_load_file_last_mod) {
                $Global::max_load_file_last_mod = $mtime;
                for my $sshlogin (values %Global::host) {
                    $sshlogin->set_max_loadavg(undef);
                }
            }
        }

        for my $sshlogin (values %Global::host) {
            debug("Running jobs before on ".$sshlogin->string().": ".$sshlogin->jobs_running()."\n");
            if($::opt_load and $sshlogin->loadavg_too_high()) {
                # The load is too high or unknown
                next;
            }
            if($::opt_noswap and $sshlogin->swapping()) {
                # The server is swapping
                next;
            }
            while ($sshlogin->jobs_running() < $sshlogin->max_jobs_running()) {
                if($Global::JobQueue->empty() and not $::opt_pipe) {
                    last;
                }
                debug($sshlogin->string()." has ".$sshlogin->jobs_running()
		      . " out of " . $sshlogin->max_jobs_running()
		      . " jobs running. Start another.\n");
                if(start_another_job($sshlogin) == 0) {
                    # No more jobs to start on this $sshlogin
                    debug("No jobs started on ".$sshlogin->string()."\n");
                    last;
                }
                debug("Job started on ".$sshlogin->string()."\n");
                $sshlogin->inc_jobs_running();
                $jobs_started++;
            }
            debug("Running jobs after on ".$sshlogin->string().": ".$sshlogin->jobs_running()
                  ." of ".$sshlogin->max_jobs_running() ."\n");
        }
    }
    return $jobs_started;
}

sub start_another_job {
    # Grab a job from Global::JobQueue, start it at sshlogin
    # and remember the pid, the STDOUT and the STDERR handles
    # Returns:
    #   1 if another jobs was started
    #   0 otherwise
    my $sshlogin = shift;
    # Do we have enough file handles to start another job?
    if(enough_file_handles()) {
        if($Global::JobQueue->empty() and not $::opt_pipe) {
            # No more commands to run
	    debug("Not starting: JobQueue empty\n");
	    return 0;
        } else {
            my $job;
            do {
		$job = get_job_with_sshlogin($sshlogin);
		if(not defined $job) {
		    # No command available for that sshlogin
		    debug("Not starting: no jobs available for ".$sshlogin->string()."\n");
		    return 0;
		}
	    } while ($job->is_already_in_joblog());
	    debug("Command to run on '".$job->sshlogin()."': '".$job->replaced()."'\n");
            if($job->start()) {
                $Global::running{$job->pid()} = $job;
		if($::opt_pipe) {
		    push(@Global::virgin_jobs,$job);
		}
                debug("Started as seq ",$job->seq()," pid:",$job->pid(),"\n");
                return 1;
            } else {
                # Not enough processes to run the job.
		# Put it back on the queue.
		$Global::JobQueue->unget($job);
		# Count down the number of jobs to run for this SSHLogin.
		my $max = $sshlogin->max_jobs_running();
		if($max > 1) { $max--; }
		$sshlogin->set_max_jobs_running($max);
		# Sleep up to 300 ms to give other processes time to die
		::usleep(rand()*300);
		::warning("No more processes: ",
			  "Decreasing number of running jobs to $max. ",
			  "Raising ulimit -u may help.\n");
		return 0;
            }
        }
    } else {
        # No more file handles
	debug("Not starting: no more file handles\n");
        return 0;
    }
}

sub drain_job_queue {
    # Returns: N/A
    $Private::first_completed ||= time;
    if($::opt_progress) {
        print $Global::original_stderr init_progress();
    }
    my $last_header="";
    my $sleep = 0.2;
    do {
        while($Global::total_running > 0) {
            debug("jobs running: ", $Global::total_running, "==", scalar
		  keys %Global::running," slots: ", $Global::max_jobs_running,
		  " Memory usage:".my_memory_usage()." ");
	    if($::opt_pipe) {
		# When using --pipe sometimes file handles are not closed properly
		for my $job (values %Global::running) {
		    my $fh = $job->stdin();
		    close $fh;
		}
	    }
            if($::opt_progress) {
                my %progress = progress();
                if($last_header ne $progress{'header'}) {
                    print $Global::original_stderr "\n",$progress{'header'},"\n";
                    $last_header = $progress{'header'};
                }
                print $Global::original_stderr "\r",$progress{'status'};
            }
            # Sometimes SIGCHLD is not registered, so force reaper
	    $sleep = ::reap_usleep($sleep);
        }
        if(not $Global::JobQueue->empty()) {
            start_more_jobs(); # These jobs may not be started because of loadavg
	    $sleep = ::reap_usleep($sleep);
        }
    } while ($Global::total_running > 0
	     or
	     not $Global::start_no_new_jobs and not $Global::JobQueue->empty());

    if($::opt_progress) {
        print $Global::original_stderr "\n";
    }
}

sub toggle_progress {
    # Turn on/off progress view
    # Returns: N/A
    $::opt_progress = not $::opt_progress;
    if($::opt_progress) {
        print $Global::original_stderr init_progress();
    }
}

sub init_progress {
    # Returns:
    #   list of computers for progress output
    $|=1;
    my %progress = progress();
    return ("\nComputers / CPU cores / Max jobs to run\n",
            $progress{'workerlist'});
}

sub progress {
    # Returns:
    #   list of workers
    #   header that will fit on the screen
    #   status message that will fit on the screen
    my $termcols = terminal_columns();
    my ($status, $header) = ("x"x($termcols+1),"");
    my @workers = sort keys %Global::host;
    my %sshlogin = map { $_ eq ":" ? ($_=>"local") : ($_=>$_) } @workers;
    my $workerno = 1;
    my %workerno = map { ($_=>$workerno++) } @workers;
    my $workerlist = "";
    for my $w (@workers) {
        $workerlist .=
        $workerno{$w}.":".$sshlogin{$w} ." / ".
            ($Global::host{$w}->ncpus() || "-")." / ".
            $Global::host{$w}->max_jobs_running()."\n";
    }
    my $eta = "";
    if($::opt_eta) {
        my $completed = 0;
        for(@workers) { $completed += $Global::host{$_}->jobs_completed() }
        if($completed) {
	    my $total = $Global::JobQueue->total_jobs();
	    my $left = $total - $completed;
	    my $pctcomplete = $completed / $total;
	    my $timepassed = (time - $Private::first_completed);
	    my $avgtime = $timepassed / $completed;
	    $Private::smoothed_avg_time ||= $avgtime;
	    # Smooth the eta so it does not jump wildly
	    $Private::smoothed_avg_time = (1 - $pctcomplete) *
		$Private::smoothed_avg_time + $pctcomplete * $avgtime;
	    my $this_eta;
	    $Private::last_time ||= $timepassed;
	    if($timepassed != $Private::last_time
	       or not defined $Private::last_eta) {
		$Private::last_time = $timepassed;
		$this_eta = $left * $Private::smoothed_avg_time;
		$Private::last_eta = $this_eta;
	    } else {
		$this_eta = $Private::last_eta;
	    }
	    $eta = sprintf("ETA: %ds %dleft %.2favg  ", $this_eta, $left, $avgtime);
        }
    }

    if(length $status > $termcols) {
        # sshlogin1:XX/XX/XX%/XX.Xs sshlogin2:XX/XX/XX%/XX.Xs sshlogin3:XX/XX/XX%/XX.Xs
        $header = "Computer:jobs running/jobs completed/%of started jobs/Average seconds to complete";
        $status = $eta .
            join(" ",map
                 {
                     if($Global::total_started) {
                         my $completed = ($Global::host{$_}->jobs_completed()||0);
                         my $running = $Global::host{$_}->jobs_running();
                         my $time = $completed ? (time-$^T)/($completed) : "0";
                         sprintf("%s:%d/%d/%d%%/%.1fs ",
                                 $sshlogin{$_}, $running, $completed,
                                 ($running+$completed)*100
                                 / $Global::total_started, $time);
                     }
                 } @workers);
    }
    if(length $status > $termcols) {
        # 1:XX/XX/XX%/XX.Xs 2:XX/XX/XX%/XX.Xs 3:XX/XX/XX%/XX.Xs 4:XX/XX/XX%/XX.Xs
        $header = "Computer:jobs running/jobs completed/%of started jobs";
        $status = $eta .
            join(" ",map
                 {
                     my $completed = ($Global::host{$_}->jobs_completed()||0);
                     my $running = $Global::host{$_}->jobs_running();
                     my $time = $completed ? (time-$^T)/($completed) : "0";
                     sprintf("%s:%d/%d/%d%%/%.1fs ",
                             $workerno{$_}, $running, $completed,
                             ($running+$completed)*100
                             / $Global::total_started, $time);
                 } @workers);
    }
    if(length $status > $termcols) {
        # sshlogin1:XX/XX/XX% sshlogin2:XX/XX/XX% sshlogin3:XX/XX/XX%
        $header = "Computer:jobs running/jobs completed/%of started jobs";
        $status = $eta .
            join(" ",map
                 { sprintf("%s:%d/%d/%d%%",
                           $sshlogin{$_},
                           $Global::host{$_}->jobs_running(),
                           ($Global::host{$_}->jobs_completed()||0),
                           ($Global::host{$_}->jobs_running()+
                            ($Global::host{$_}->jobs_completed()||0))*100
                           / $Global::total_started) }
                 @workers);
    }
    if(length $status > $termcols) {
        # 1:XX/XX/XX% 2:XX/XX/XX% 3:XX/XX/XX% 4:XX/XX/XX% 5:XX/XX/XX% 6:XX/XX/XX%
        $header = "Computer:jobs running/jobs completed/%of started jobs";
        $status = $eta .
            join(" ",map
                 { sprintf("%s:%d/%d/%d%%",
                           $workerno{$_},
                           $Global::host{$_}->jobs_running(),
                           ($Global::host{$_}->jobs_completed()||0),
                           ($Global::host{$_}->jobs_running()+
                            ($Global::host{$_}->jobs_completed()||0))*100
                           / $Global::total_started) }
                 @workers);
    }
    if(length $status > $termcols) {
        # sshlogin1:XX/XX/XX% sshlogin2:XX/XX/XX% sshlogin3:XX/XX sshlogin4:XX/XX
        $header = "Computer:jobs running/jobs completed";
        $status = $eta .
            join(" ",map
                       { sprintf("%s:%d/%d",
                                 $sshlogin{$_}, $Global::host{$_}->jobs_running(),
                                 ($Global::host{$_}->jobs_completed()||0)) }
                       @workers);
    }
    if(length $status > $termcols) {
        # sshlogin1:XX/XX sshlogin2:XX/XX sshlogin3:XX/XX sshlogin4:XX/XX
        $header = "Computer:jobs running/jobs completed";
        $status = $eta .
            join(" ",map
                       { sprintf("%s:%d/%d",
                                 $sshlogin{$_}, $Global::host{$_}->jobs_running(),
                                 ($Global::host{$_}->jobs_completed()||0)) }
                       @workers);
    }
    if(length $status > $termcols) {
        # 1:XX/XX 2:XX/XX 3:XX/XX 4:XX/XX 5:XX/XX 6:XX/XX
        $header = "Computer:jobs running/jobs completed";
        $status = $eta .
            join(" ",map
                       { sprintf("%s:%d/%d",
                                 $workerno{$_}, $Global::host{$_}->jobs_running(),
                                 ($Global::host{$_}->jobs_completed()||0)) }
                       @workers);
    }
    if(length $status > $termcols) {
        # sshlogin1:XX sshlogin2:XX sshlogin3:XX sshlogin4:XX sshlogin5:XX
        $header = "Computer:jobs completed";
        $status = $eta .
            join(" ",map
                       { sprintf("%s:%d",
                                 $sshlogin{$_},
                                 ($Global::host{$_}->jobs_completed()||0)) }
                       @workers);
    }
    if(length $status > $termcols) {
        # 1:XX 2:XX 3:XX 4:XX 5:XX 6:XX
        $header = "Computer:jobs completed";
        $status = $eta .
            join(" ",map
                       { sprintf("%s:%d",
                                 $workerno{$_},
                                 ($Global::host{$_}->jobs_completed()||0)) }
                       @workers);
    }
    return ("workerlist" => $workerlist, "header" => $header, "status" => $status);
}

sub terminal_columns {
    # Get the number of columns of the display
    # Returns:
    #   number of columns of the screen
    if(not $Private::columns) {
        $Private::columns = $ENV{'COLUMNS'};
        if(not $Private::columns) {
            my $resize = qx{ resize 2>/dev/null };
            $resize =~ /COLUMNS=(\d+);/ and do { $Private::columns = $1; };
        }
        $Private::columns ||= 80;
    }
    return $Private::columns;
}

sub get_job_with_sshlogin {
    # Returns:
    #   next command to run with ssh command wrapping if remote
    #   next command to run with no wrapping (clean_command)
    my $sshlogin = shift;

    if($::oodebug and $Global::JobQueue->empty()) {
        Carp::confess("get_job_with_sshlogin should never be called if empty");
    }

    my $job = $Global::JobQueue->get();
    if(not defined $job) {
        # No more jobs
	::debug("No more jobs: JobQueue empty\n");
        return undef;
    }

    if($::oodebug and not defined $job->{'commandline'}) {
        Carp::confess("get_job_with_sshlogin job->commandline should never be empty");
    }
    my $clean_command = $job->replaced();
    if($clean_command =~ /^\s*$/) {
        # Do not run empty lines
        if(not $Global::JobQueue->empty()) {
            return get_job_with_sshlogin($sshlogin);
        } else {
            return undef;
        }
    }
    $job->set_sshlogin($sshlogin);
    if($::opt_retries and $clean_command and
       $job->failed_here()) {
        # This command with these args failed for this sshlogin
        my ($no_of_failed_sshlogins,$min_failures) = $job->min_failed();
        #::my_dump(($no_of_failed_sshlogins,$min_failures));
        if($no_of_failed_sshlogins == keys %Global::host and
           $job->failed_here() == $min_failures) {
            # It failed the same or more times on another host:
            # run it on this host
        } else {
            # If it failed fewer times on another host:
            # Find another job to run
            my $nextjob;
            if(not $Global::JobQueue->empty()) {
		# This can potentially recurse for all args
                no warnings 'recursion';
                $nextjob = get_job_with_sshlogin($sshlogin);
            }
            # Push the command back on the queue
            $Global::JobQueue->unget($job);
            return $nextjob;
        }
    }
    return $job;
}

sub __REMOTE_SSH__ {}

sub read_sshloginfiles {
    # Returns: N/A
    for (@_) {
	read_sshloginfile($_);
    }
}

sub read_sshloginfile {
    # Returns: N/A
    my $file = shift;
    my $close = 1;
    if($file eq "..") {
        $file = $ENV{'HOME'}."/.parallel/sshloginfile";
    }
    if($file eq ".") {
        $file = "/etc/parallel/sshloginfile";
    }
    if($file eq "-") {
	*IN = *STDIN;
	$close = 0;
    } else {
	if(not open(IN, $file)) {
	    ::error("Cannot open $file.\n");
	    ::wait_and_exit(255);
	}
    }
    while(<IN>) {
        chomp;
        /^\s*#/ and next;
        /^\s*$/ and next;
        push @Global::sshlogin, $_;
    }
    if($close) {
	close IN;
    }
}

sub parse_sshlogin {
    # Returns: N/A
    my @login;
    if(not @Global::sshlogin) { @Global::sshlogin = (":"); }
    for my $sshlogin (@Global::sshlogin) {
        # Split up -S sshlogin,sshlogin
        for my $s (split /,/, $sshlogin) {
            if ($s eq ".." or $s eq "-") {
                read_sshloginfile($s);
            } else {
                push (@login, $s);
            }
        }
    }
    for my $sshlogin_string (@login) {
        my $sshlogin = SSHLogin->new($sshlogin_string);
        $sshlogin->set_maxlength(Limits::Command::max_length());
        $Global::host{$sshlogin->string()} = $sshlogin;
    }
    debug("sshlogin: ", my_dump(%Global::host),"\n");
    if($::opt_transfer or @::opt_return or $::opt_cleanup or @::opt_basefile) {
        if(not remote_hosts()) {
            # There are no remote hosts
            if(@::opt_trc) {
		::warning("--trc ignored as there are no remote --sshlogin.\n");
            } elsif (defined $::opt_transfer) {
		::warning("--transfer ignored as there are no remote --sshlogin.\n");
            } elsif (@::opt_return) {
                ::warning("--return ignored as there are no remote --sshlogin.\n");
            } elsif (defined $::opt_cleanup) {
		::warning("--cleanup ignored as there are no remote --sshlogin.\n");
            } elsif (@::opt_basefile) {
                ::warning("--basefile ignored as there are no remote --sshlogin.\n");
            }
        }
    }
}

sub remote_hosts {
    # Return sshlogins that are not ':'
    # Returns:
    #   list of sshlogins with ':' removed
    return grep !/^:$/, keys %Global::host;
}

sub setup_basefile {
    # Transfer basefiles to each $sshlogin
    # This needs to be done before first jobs on $sshlogin is run
    # Returns: N/A
    my $cmd = "";
    for my $sshlogin (values %Global::host) {
        if($sshlogin->string() eq ":") { next }
        my $sshcmd = $sshlogin->sshcommand();
        my $serverlogin = $sshlogin->serverlogin();
        my $rsync_opt = "-rlDzR -e".shell_quote_scalar($sshcmd);
        for my $file (@::opt_basefile) {
            my $f = $file;
            my $relpath = ($f !~ m:^/:); # Is the path relative?
            # Use different subdirs depending on abs or rel path
            my $rsync_destdir = ($relpath ? "./" : "/");
            $f =~ s:/\./:/:g; # Rsync treats /./ special. We dont want that
            $f = shell_quote_scalar($f);
            $cmd .= "rsync $rsync_opt $f $serverlogin:$rsync_destdir &";
        }
    }
    $cmd .= "wait;";
    debug("basesetup: $cmd\n");
    print `$cmd`;
}

sub cleanup_basefile {
    # Remove the basefiles transferred
    # Returns: N/A
    my $cmd="";
    for my $sshlogin (values %Global::host) {
        if($sshlogin->string() eq ":") { next }
        my $sshcmd = $sshlogin->sshcommand();
        my $serverlogin = $sshlogin->serverlogin();
        for my $file (@::opt_basefile) {
            $cmd .= "$sshcmd $serverlogin rm -f ".shell_quote_scalar(shell_quote_scalar($file))."&";
        }
    }
    $cmd .= "wait;";
    debug("basecleanup: $cmd\n");
    print `$cmd`;
}

sub __SIGNAL_HANDLING__ {}

sub list_running_jobs {
    # Returns: N/A
    for my $v (values %Global::running) {
        print $Global::original_stderr "$Global::progname: ",$v->replaced(),"\n";
    }
}

sub start_no_new_jobs {
    # Returns: N/A
    $SIG{TERM} = $Global::original_sig{TERM};
    print $Global::original_stderr
        ("$Global::progname: SIGTERM received. No new jobs will be started.\n",
         "$Global::progname: Waiting for these ", scalar(keys %Global::running),
         " jobs to finish. Send SIGTERM again to stop now.\n");
    list_running_jobs();
    $Global::start_no_new_jobs++;
}

sub reaper {
    # A job finished.
    # Print the output.
    # Start another job
    # Returns: N/A
    my $stiff;
    my $children_reaped = 0;
    debug("Reaper called ");
    while (($stiff = waitpid(-1, &WNOHANG)) > 0) {
	$children_reaped++;
        if($Global::sshmaster{$stiff}) {
            # This is one of the ssh -M: ignore
            next;
        }
        my $job = $Global::running{$stiff};
	# '-a <(seq 10)' will give us a pid not in %Global::running
        $job or next;
        $job->set_exitstatus($? >> 8);
        $job->set_exitsignal($? & 127);
        debug("died (".$job->exitstatus()."): ".$job->seq());
        $job->set_endtime();
        if($stiff == $Global::tty_taken) {
            # The process that died had the tty => release it
            $Global::tty_taken = 0;
        }

        if(not $job->should_be_retried()) {
            # Force printing now if the job failed and we are going to exit
            my $print_now = ($job->exitstatus() and
                             $::opt_halt_on_error and $::opt_halt_on_error == 2);
            if($Global::keeporder and not $print_now) {
                $Private::print_later{$job->seq()} = $job;
                $Private::job_end_sequence ||= 1;
                debug("Looking for: $Private::job_end_sequence ".
                      "Current: ".$job->seq()."\n");
                while($Private::print_later{$Private::job_end_sequence}) {
                    debug("Found job end $Private::job_end_sequence");
                    $Private::print_later{$Private::job_end_sequence}->print();
                    delete $Private::print_later{$Private::job_end_sequence};
                    $Private::job_end_sequence++;
                }
            } else {
                $job->print();
            }
            if($job->exitstatus()) {
                # The jobs had a exit status <> 0, so error
                $Global::exitstatus++;
                if($::opt_halt_on_error) {
                    if($::opt_halt_on_error == 1) {
                        # If halt on error == 1 we should gracefully exit
                        print $Global::original_stderr
                            ("$Global::progname: Starting no more jobs. ",
                             "Waiting for ", scalar(keys %Global::running),
                             " jobs to finish. This job failed:\n",
                             $job->replaced(),"\n");
                        $Global::start_no_new_jobs++;
                        $Global::halt_on_error_exitstatus = $job->exitstatus();
                    } elsif($::opt_halt_on_error == 2) {
                        # If halt on error == 2 we should exit immediately
                        print $Global::original_stderr
                            ("$Global::progname: This job failed:\n",
                             $job->replaced(),"\n");
                        exit ($job->exitstatus());
                    }
                }
            }
        }
        my $sshlogin = $job->sshlogin();
        $sshlogin->dec_jobs_running();
        $sshlogin->inc_jobs_completed();
        $Global::total_running--;
        delete $Global::running{$stiff};
        start_more_jobs();
    }
    debug("Reaper exit\n");
    return $children_reaped;
}

sub timeout {
    # SIGALRM was received. Check if there was a timeout
    # @Global::timeout is sorted by timeout
    while (@Global::timeouts) {
	my $t = $Global::timeouts[0];
	if($t->timed_out()) {
	    $t->kill();
	    shift @Global::timeouts;
	} else {
	    # Because they are sorted by timeout
	    last;
	}
    }
}


sub __USAGE__ {}

sub wait_and_exit {
    # If we do not wait, we sometimes get segfault
    # Returns: N/A
    for (keys %Global::unkilled_children) {
        kill 9, $_;
        waitpid($_,0);
        delete $Global::unkilled_children{$_};
    }
    wait();
    exit(shift);
}

sub die_usage {
    # Returns: N/A
    usage();
    wait_and_exit(255);
}

sub usage {
    # Returns: N/A
    print join
	("\n",
	 "Usage:",
	 "$Global::progname [options] [command [arguments]] < list_of_arguments",
	 "$Global::progname [options] [command [arguments]] (::: arguments|:::: argfile(s))...",
	 "cat ... | $Global::progname --pipe [options] [command [arguments]]",
	 "",
	 "-j n           Run n jobs in parallel",
	 "-k             Keep same order",
	 "-X             Multiple arguments with context replace",
	 "--colsep regexp      Split input on regexp for positional replacements",
	 "{} {.} {/} {/.} {#}  Replacement strings",
	 "{3} {3.} {3/} {3/.}  Positional replacement strings",
	 "",
	 "-S sshlogin    Example: foo\@server.example.com",
	 "--slf ..       Use ~/.parallel/sshloginfile as the list of sshlogins",
	 "--trc {}.bar   Shorthand for --transfer --return {}.bar --cleanup",
	 "--onall        Run the given command with argument on all sshlogins",
	 "--nonall       Run the given command with no arguments on all sshlogins",
	 "",
	 "--pipe         Split stdin (standard input) to multiple jobs.",
	 "--recend str   Record end separator for --pipe.",
	 "--recstart str Record start separator for --pipe.",
	 "",
	 "See 'man $Global::progname' for details",
	 "",
	 "When using GNU Parallel for a publication please cite:",
	 "",
	 "O. Tange (2011): GNU Parallel - The Command-Line Power Tool,",
	 ";login: The USENIX Magazine, February 2011:42-47.",
	 "");
}

sub warning {
    my @w = @_;
    my $fh = $Global::original_stderr || *STDERR;
    my $prog = $Global::progname || "parallel";
    print $fh $prog, ": Warning: ", @w;
}


sub error {
    my @w = @_;
    my $fh = $Global::original_stderr || *STDERR;
    my $prog = $Global::progname || "parallel";
    print $fh $prog, ": Error: ", @w;
}


sub die_bug {
    my $bugid = shift;
    print STDERR
	("$Global::progname: This should not happen. You have found a bug.\n",
	 "Please contact <parallel\@gnu.org> and include:\n",
	 "* The version number: $Global::version\n",
	 "* The bugid: $bugid\n",
	 "* The command line being run\n",
	 "* The files being read (put the files on a webserver if they are big)\n",
	 "\n",
	 "If you get the error on smaller/fewer files, please include those instead.\n");
    ::wait_and_exit(255);
}

sub version {
    # Returns: N/A
    if($::opt_tollef and not $::opt_gnu) {
	print "WARNING: YOU ARE USING --tollef. USE --gnu FOR GNU PARALLEL\n\n";
    }
    print join("\n",
               "GNU $Global::progname $Global::version",
               "Copyright (C) 2007,2008,2009,2010,2011,2012 Ole Tange and Free Software Foundation, Inc.",
               "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>",
               "This is free software: you are free to change and redistribute it.",
               "GNU $Global::progname comes with no warranty.",
               "",
               "Web site: http://www.gnu.org/software/${Global::progname}\n",
	       "When using GNU Parallel for a publication please cite:\n",
	       "O. Tange (2011): GNU Parallel - The Command-Line Power Tool, ",
	       ";login: The USENIX Magazine, February 2011:42-47.\n",
        );
}

sub bibtex {
    # Returns: N/A
    if($::opt_tollef and not $::opt_gnu) {
	print "WARNING: YOU ARE USING --tollef. USE --gnu FOR GNU PARALLEL\n\n";
    }
    print join("\n",
               "\@article{Tange2011a,",
	       " title = {GNU Parallel - The Command-Line Power Tool},",
	       " author = {O. Tange},",
	       " address = {Frederiksberg, Denmark},",
	       " journal = {;login: The USENIX Magazine},",
	       " month = {Feb},",
	       " number = {1},",
	       " volume = {36},",
	       " url = {http://www.gnu.org/s/parallel},",
	       " year = {2011},",
	       " pages = {42-47}",
	       "}",
	       "",
        );
}

sub show_limits {
    # Returns: N/A
    print("Maximal size of command: ",Limits::Command::real_max_length(),"\n",
          "Maximal used size of command: ",Limits::Command::max_length(),"\n",
          "\n",
          "Execution of  will continue now, and it will try to read its input\n",
          "and run commands; if this is not what you wanted to happen, please\n",
          "press CTRL-D or CTRL-C\n");
}

sub __GENERIC_COMMON_FUNCTION__ {}

sub min {
    # Returns:
    #   Minimum value of array
    my $min;
    for (@_) {
        # Skip undefs
        defined $_ or next;
        defined $min or do { $min = $_; next; }; # Set $_ to the first non-undef
        $min = ($min < $_) ? $min : $_;
    }
    return $min;
}

sub max {
    # Returns:
    #   Maximum value of array
    my $max;
    for (@_) {
        # Skip undefs
        defined $_ or next;
        defined $max or do { $max = $_; next; }; # Set $_ to the first non-undef
        $max = ($max > $_) ? $max : $_;
    }
    return $max;
}

sub sum {
    # Returns:
    #   Sum of values of array
    my @args = @_;
    my $sum = 0;
    for (@args) {
        # Skip undefs
        $_ and do { $sum += $_; }
    }
    return $sum;
}

sub undef_as_zero {
    my $a = shift;
    return $a ? $a : 0;
}

sub undef_as_empty {
    my $a = shift;
    return $a ? $a : "";
}

sub hostname {
    if(not $Private::hostname) {
        my $hostname = `hostname`;
        chomp($hostname);
        $Private::hostname = $hostname || "nohostname";
    }
    return $Private::hostname;
}

sub reap_usleep {
    # Reap dead children.
    # If no children: Sleep specified amount with exponential backoff
    # Returns:
    #   0.00001 if children reaped (0.00001 ms works best on highend)
    #   $ms*1.1 if no children reaped
    my $ms = shift;
    if(reaper()) {
	return 0.00001;
    } else {
	usleep($ms);
	return (($ms < 1000) ? ($ms * 1.1) : ($ms)); # exponential back off
    }
}

sub usleep {
    # Sleep this many milliseconds.
    my $secs = shift;
    ::debug("Sleeping ",$secs," millisecs\n");
    select(undef, undef, undef, $secs/1000);
    if($::opt_timeout) {
	::debug(my_dump($Global::timeoutq));
	$Global::timeoutq->process_timeouts();
    }
}

sub hires_time {
    # Returns time since epoch as float

    if(not $Global::use{"Time::HiRes"}) {
	if(eval "use Time::HiRes qw ( time );") {
	    eval "sub TimeHiRestime { return Time::HiRes::time };";
	} else {
	    eval "sub TimeHiRestime { return time() };";
	}
	$Global::use{"Time::HiRes"} = 1;
    }

    return TimeHiRestime();
}

sub multiply_binary_prefix {
    # Evalualte numbers with binary prefix
    # k=10^3, m=10^6, g=10^9, t=10^12, p=10^15, e=10^18, z=10^21, y=10^24
    # K=2^10, M=2^20, G=2^30, T=2^40, P=2^50, E=2^70, Z=2^80, Y=2^80
    # Ki=2^10, Mi=2^20, Gi=2^30, Ti=2^40, Pi=2^50, Ei=2^70, Zi=2^80, Yi=2^80
    # ki=2^10, mi=2^20, gi=2^30, ti=2^40, pi=2^50, ei=2^70, zi=2^80, yi=2^80
    # 13G = 13*1024*1024*1024 = 13958643712
    my $s = shift;
    $s =~ s/k/*1000/g;
    $s =~ s/M/*1000*1000/g;
    $s =~ s/G/*1000*1000*1000/g;
    $s =~ s/T/*1000*1000*1000*1000/g;
    $s =~ s/P/*1000*1000*1000*1000*1000/g;
    $s =~ s/E/*1000*1000*1000*1000*1000*1000/g;
    $s =~ s/Z/*1000*1000*1000*1000*1000*1000*1000/g;
    $s =~ s/Y/*1000*1000*1000*1000*1000*1000*1000*1000/g;
    $s =~ s/X/*1000*1000*1000*1000*1000*1000*1000*1000*1000/g;

    $s =~ s/Ki?/*1024/gi;
    $s =~ s/Mi?/*1024*1024/gi;
    $s =~ s/Gi?/*1024*1024*1024/gi;
    $s =~ s/Ti?/*1024*1024*1024*1024/gi;
    $s =~ s/Pi?/*1024*1024*1024*1024*1024/gi;
    $s =~ s/Ei?/*1024*1024*1024*1024*1024*1024/gi;
    $s =~ s/Zi?/*1024*1024*1024*1024*1024*1024*1024/gi;
    $s =~ s/Yi?/*1024*1024*1024*1024*1024*1024*1024*1024/gi;
    $s =~ s/Xi?/*1024*1024*1024*1024*1024*1024*1024*1024*1024/gi;
    $s = eval $s;
    return $s;
}

sub __DEBUGGING__ {}

sub debug {
    # Returns: N/A
    $Global::debug or return;
    @_ = grep { defined $_ ? $_ : "" } @_;
    if($Global::original_stdout) {
        print $Global::original_stdout @_;
    } else {
        print @_;
    }
}

sub my_memory_usage {
    # Returns:
    #   memory usage if found
    #   0 otherwise
    use strict;
    use FileHandle;

    my $pid = $$;
    if(-e "/proc/$pid/stat") {
        my $fh = FileHandle->new("</proc/$pid/stat");

        my $data = <$fh>;
        chomp $data;
        $fh->close;

        my @procinfo = split(/\s+/,$data);

        return undef_as_zero($procinfo[22]);
    } else {
        return 0;
    }
}

sub my_size {
    # Returns:
    #   size of object if Devel::Size is installed
    #   -1 otherwise
    my @size_this = (@_);
    eval "use Devel::Size qw(size total_size)";
    if ($@) {
        return -1;
    } else {
        return total_size(@_);
    }
}

sub my_dump {
    # Returns:
    #   ascii expression of object if Data::Dump(er) is installed
    #   error code otherwise
    my @dump_this = (@_);
    eval "use Data::Dump qw(dump);";
    if ($@) {
        # Data::Dump not installed
        eval "use Data::Dumper;";
        if ($@) {
            my $err =  "Neither Data::Dump nor Data::Dumper is installed\n".
                "Not dumping output\n";
            print $Global::original_stderr $err;
            return $err;
        } else {
            return Dumper(@dump_this);
        }
    } else {
	# Create a dummy Data::Dump:dump as Hans Schou sometimes has
	# it undefined
	eval "sub Data::Dump:dump {}";
        eval "use Data::Dump qw(dump);";
        return (Data::Dump::dump(@dump_this));
    }
}

sub __OBJECT_ORIENTED_PARTS__ {}

package SSHLogin;

sub new {
    my $class = shift;
    my $sshlogin_string = shift;
    my $ncpus;
    if($sshlogin_string =~ s:^(\d+)/:: and $1) {
        # Override default autodetected ncpus unless zero or missing
        $ncpus = $1;
    }
    my $string = $sshlogin_string;
    my @unget = ();
    my $no_slash_string = $string;
    $no_slash_string =~ s/[^-a-z0-9:]/_/gi;
    return bless {
        'string' => $string,
        'jobs_running' => 0,
        'jobs_completed' => 0,
        'maxlength' => undef,
        'max_jobs_running' => undef,
        'ncpus' => $ncpus,
        'sshcommand' => undef,
        'serverlogin' => undef,
        'control_path_dir' => undef,
        'control_path' => undef,
	'time_to_login' => undef,
        'loadavg_file' => $ENV{'HOME'} . "/.parallel/tmp/loadavg-" .
            $$."-".$no_slash_string,
        'loadavg' => undef,
	'last_loadavg_update' => 0,
        'swap_activity_file' => $ENV{'HOME'} . "/.parallel/tmp/swap_activity-" .
            $$."-".$no_slash_string,
        'swap_activity' => undef,
    }, ref($class) || $class;
}

sub DESTROY {
    my $self = shift;
    # Remove temporary files if they are created.
    unlink $self->{'loadavg_file'};
    unlink $self->{'swap_activity_file'};
}

sub string {
    my $self = shift;
    return $self->{'string'};
}

sub jobs_running {
    my $self = shift;

    return ($self->{'jobs_running'} || "0");
}

sub inc_jobs_running {
    my $self = shift;
    $self->{'jobs_running'}++;
}

sub dec_jobs_running {
    my $self = shift;
    $self->{'jobs_running'}--;
}

#sub set_jobs_running {
#    my $self = shift;
#    $self->{'jobs_running'} = shift;
#}

sub set_maxlength {
    my $self = shift;
    $self->{'maxlength'} = shift;
}

sub maxlength {
    my $self = shift;
    return $self->{'maxlength'};
}

sub jobs_completed {
    my $self = shift;
    return $self->{'jobs_completed'};
}

sub inc_jobs_completed {
    my $self = shift;
    $self->{'jobs_completed'}++;
}

sub set_max_jobs_running {
    my $self = shift;
    if(defined $self->{'max_jobs_running'}) {
        $Global::max_jobs_running -= $self->{'max_jobs_running'};
    }
    $self->{'max_jobs_running'} = shift;
    if(defined $self->{'max_jobs_running'}) {
        # max_jobs_running could be resat if -j is a changed file
        $Global::max_jobs_running += $self->{'max_jobs_running'};
    }
}

sub swapping {
    my $self = shift;
    my $swapping = $self->swap_activity();
    return (not defined $swapping or $swapping)
}

sub swap_activity {
    # If the currently known swap activity is too old:
    #   Recompute a new one in the background
    # Returns:
    #   last swap activity computed
    my $self = shift;
    # Should we update the swap_activity file?
    my $update_swap_activity_file = 0;
    if(-r $self->{'swap_activity_file'}) {
        open(SWAP,"<".$self->{'swap_activity_file'}) || ::die_bug("swap_activity_file-r");
        my $swap_out = <SWAP>;
        close SWAP;
        if($swap_out =~ /^(\d+)$/) {
            $self->{'swap_activity'} = $1;
            ::debug("New swap_activity: ".$self->{'swap_activity'});
        }
        ::debug("Last update: ".$self->{'last_swap_activity_update'});
        if(time - $self->{'last_swap_activity_update'} > 10) {
            # last swap activity update was started 10 seconds ago
            ::debug("Older than 10 sec: ".$self->{'swap_activity_file'});
            $update_swap_activity_file = 1;
        }
    } else {
        ::debug("No swap_activity file: ".$self->{'swap_activity_file'});
        $self->{'swap_activity'} = undef;
        $update_swap_activity_file = 1;
    }
    if($update_swap_activity_file) {
        ::debug("Updating swap_activity file".$self->{'swap_activity_file'});
        $self->{'last_swap_activity_update'} = time;
        -e $ENV{'HOME'}."/.parallel" or mkdir $ENV{'HOME'}."/.parallel";
        -e $ENV{'HOME'}."/.parallel/tmp" or mkdir $ENV{'HOME'}."/.parallel/tmp";
        my $swap_activity;
	# If the (remote) machine is Mac we should use vm_stat
	# swap_in and swap_out on GNU/Linux is $7 and $8
	# swap_in and swap_out on Mac is $10 and $11
	$swap_activity = q[ { vmstat 1 2 2> /dev/null || vm_stat 1; } | ].
	    q[ awk 'NR!=4{next} NF==16{print $7*$8} NF==11{print $10*$11} {exit}' ];
        if($self->{'string'} ne ":") {
            $swap_activity = $self->sshcommand() . " " . $self->serverlogin() . " " .
		::shell_quote_scalar($swap_activity);
        }
        # Run swap_activity measuring.
        # As the command can take long to run if run remote
        # save it to a tmp file before moving it to the correct file
        my $file = $self->{'swap_activity_file'};
        my $tmpfile = $self->{'swap_activity_file'}.$$;
        qx{ ($swap_activity > $tmpfile; mv $tmpfile $file) & };
    }
    return $self->{'swap_activity'};
}

sub loadavg_too_high {
    my $self = shift;
    my $loadavg = $self->loadavg();
    return (not defined $loadavg or
            $loadavg > $self->max_loadavg());
}

sub loadavg {
    # If the currently know loadavg is too old:
    #   Recompute a new one in the background
    # Returns:
    #   last load average computed
    my $self = shift;
    # Should we update the loadavg file?
    my $update_loadavg_file = 0;
    if(-r $self->{'loadavg_file'}) {
        open(UPTIME,"<".$self->{'loadavg_file'}) || ::die_bug("loadavg_file-r");
	local $/ = undef;
        my $uptime_out = <UPTIME>;
        close UPTIME;
        # load average: 0.76, 1.53, 1.45
        if($uptime_out =~ /load average: (\d+.\d+)/) {
            $self->{'loadavg'} = $1;
            ::debug("New loadavg: ".$self->{'loadavg'});
        } else {
	    ::die_bug("loadavg_invalid_content: $uptime_out");
	}
        ::debug("Last update: ".$self->{'last_loadavg_update'});
        if(time - $self->{'last_loadavg_update'} > 10) {
            # last loadavg was started 10 seconds ago
            ::debug("Older than 10 sec: ".$self->{'loadavg_file'});
            $update_loadavg_file = 1;
        }
    } else {
        ::debug("No loadavg file: ".$self->{'loadavg_file'});
        $self->{'loadavg'} = undef;
        $update_loadavg_file = 1;
    }
    if($update_loadavg_file) {
        ::debug("Updating loadavg file".$self->{'loadavg_file'}."\n");
        $self->{'last_loadavg_update'} = time;
        -e $ENV{'HOME'}."/.parallel" or mkdir $ENV{'HOME'}."/.parallel";
        -e $ENV{'HOME'}."/.parallel/tmp" or mkdir $ENV{'HOME'}."/.parallel/tmp";
        my $uptime;
        if($self->{'string'} eq ":") {
            $uptime = "LANG=C uptime";
        } else {
            $uptime = $self->sshcommand() . " " . $self->serverlogin() . " LANG=C uptime";
        }
        # Run uptime.
        # As the command can take long to run if run remote
        # save it to a tmp file before moving it to the correct file
        my $file = $self->{'loadavg_file'};
        my $tmpfile = $self->{'loadavg_file'}.$$;
        qx{ ($uptime > $tmpfile && mv $tmpfile $file) & };
    }
    return $self->{'loadavg'};
}

sub max_loadavg {
    my $self = shift;
    if(not defined $self->{'max_loadavg'}) {
        $self->{'max_loadavg'} =
            $self->compute_max_loadavg($::opt_load);
    }
    ::debug("max_loadavg: ".$self->string()." ".$self->{'max_loadavg'});
    return $self->{'max_loadavg'};
}

sub set_max_loadavg {
    my $self = shift;
    $self->{'max_loadavg'} = shift;
}

sub compute_max_loadavg {
    # Parse the max loadaverage that the user asked for using --load
    # Returns:
    #   max loadaverage
    my $self = shift;
    my $loadspec = shift;
    my $load;
    if(defined $loadspec) {
        if($loadspec =~ /^\+(\d+)$/) {
            # E.g. --load +2
            my $j = $1;
            $load =
                $self->ncpus() + $j;
        } elsif ($loadspec =~ /^-(\d+)$/) {
            # E.g. --load -2
            my $j = $1;
            $load =
                $self->ncpus() - $j;
        } elsif ($loadspec =~ /^(\d+)\%$/) {
            my $j = $1;
            $load =
                $self->ncpus() * $j / 100;
        } elsif ($loadspec =~ /^(\d+(\.\d+)?)$/) {
            $load = $1;
        } elsif (-f $loadspec) {
            $Global::max_load_file = $loadspec;
            $Global::max_load_file_last_mod = (stat($Global::max_load_file))[9];
            if(open(IN, $Global::max_load_file)) {
                my $opt_load_file = join("",<IN>);
                close IN;
                $load = $self->compute_max_loadavg($opt_load_file);
            } else {
                print $Global::original_stderr "Cannot open $loadspec\n";
                ::wait_and_exit(255);
            }
        } else {
            print $Global::original_stderr "Parsing of --load failed\n";
            ::die_usage();
        }
        if($load < 0.01) {
            $load = 0.01;
        }
    }
    return $load;
}

sub time_to_login {
    my $self = shift;
    return $self->{'time_to_login'};
}

sub set_time_to_login {
    my $self = shift;
    $self->{'time_to_login'} = shift;
}

sub max_jobs_running {
    my $self = shift;
    if(not defined $self->{'max_jobs_running'}) {
        my $nproc = $self->compute_number_of_processes($::opt_P);
        $self->set_max_jobs_running($nproc);
    }
    return $self->{'max_jobs_running'};
}

sub compute_number_of_processes {
    # Number of processes wanted and limited by system resources
    # Returns:
    #   Number of processes
    my $self = shift;
    my $opt_P = shift;
    my $wanted_processes = $self->user_requested_processes($opt_P);
    if(not defined $wanted_processes) {
        $wanted_processes = $Global::default_simultaneous_sshlogins;
    }
    ::debug("Wanted procs: $wanted_processes\n");
    my $system_limit =
        $self->processes_available_by_system_limit($wanted_processes);
    ::debug("Limited to procs: $system_limit\n");
    return $system_limit;
}

sub processes_available_by_system_limit {
    # If the wanted number of processes is bigger than the system limits:
    # Limit them to the system limits
    # Limits are: File handles, number of input lines, processes,
    # and taking > 1 second to spawn 10 extra processes
    # Returns:
    #   Number of processes
    my $self = shift;
    my $wanted_processes = shift;

    my $system_limit = 0;
    my @jobs = ();
    my $job;
    my @args = ();
    my $arg;
    my $more_filehandles = 1;
    my $max_system_proc_reached = 0;
    my $slow_spawining_warning_printed = 0;
    my $time = time;
    my %fh;
    my @children;

    # Reserve filehandles
    # perl uses 7 filehandles for something?
    # parallel uses 1 for memory_usage
    for my $i (1..8) {
        open($fh{"init-$i"},"</dev/null");
    }

    for(1..2) {
        # System process limit
        my $child;
        if($child = fork()) {
            push (@children,$child);
            $Global::unkilled_children{$child} = 1;
        } elsif(defined $child) {
            # The child takes one process slot
            # It will be killed later
            $SIG{TERM} = $Global::original_sig{TERM};
            sleep 10000000;
            exit(0);
        } else {
            $max_system_proc_reached = 1;
        }
    }
    my $count_jobs_already_read = $Global::JobQueue->next_seq();
    my $wait_time_for_getting_args = 0;
    my $start_time = time;
    while(1) {
        $system_limit >= $wanted_processes and last;
        not $more_filehandles and last;
        $max_system_proc_reached and last;
	my $before_getting_arg = time;
        if($Global::semaphore) {
	    # Skip
        } elsif(defined $::opt_retries and $count_jobs_already_read) {
            # For retries we may need to run all jobs on this sshlogin
            # so include the already read jobs for this sshlogin
            $count_jobs_already_read--;
        } else {
            if($::opt_X or $::opt_m) {
                # The arguments may have to be re-spread over several jobslots
                # So pessimistically only read one arg per jobslot
                # instead of a full commandline
                if($Global::JobQueue->{'commandlinequeue'}->{'arg_queue'}->empty()) {
		    if($Global::JobQueue->empty()) {
			last;
		    } else {
			($job) = $Global::JobQueue->get();
			push(@jobs, $job);
		    }
		} else {
		    ($arg) = $Global::JobQueue->{'commandlinequeue'}->{'arg_queue'}->get();
		    push(@args, $arg);
		}
            } else {
                # If there are no more command lines, then we have a process
                # per command line, so no need to go further
                $Global::JobQueue->empty() and last;
                ($job) = $Global::JobQueue->get();
                push(@jobs, $job);
	    }
        }
	$wait_time_for_getting_args += time - $before_getting_arg;
        $system_limit++;

        # Every simultaneous process uses 2 filehandles when grouping
        $more_filehandles = open($fh{$system_limit*10},"</dev/null")
            && open($fh{$system_limit*10+2},"</dev/null");

        # System process limit
        my $child;
        if($child = fork()) {
            push (@children,$child);
            $Global::unkilled_children{$child} = 1;
        } elsif(defined $child) {
            # The child takes one process slot
            # It will be killed later
            $SIG{TERM} = $Global::original_sig{TERM};
            sleep 10000000;
            exit(0);
        } else {
            $max_system_proc_reached = 1;
        }
	my $forktime = time - $time - $wait_time_for_getting_args;
        ::debug("Time to fork $system_limit procs: $wait_time_for_getting_args ",
		$forktime,
		" (processes so far: ", $system_limit,")\n");
        if($system_limit > 10 and
	   $forktime > 1 and
	   $forktime > $system_limit * 0.01
	   and not $slow_spawining_warning_printed) {
            # It took more than 0.01 second to fork a processes on avg.
            # Give the user a warning. He can press Ctrl-C if this
            # sucks.
            print $Global::original_stderr
                ("parallel: Warning: Starting $system_limit processes took > $forktime sec.\n",
                 "Consider adjusting -j. Press CTRL-C to stop.\n");
            $slow_spawining_warning_printed = 1;
        }
    }
    # Cleanup: Close the files
    for (values %fh) { close $_ }
    # Cleanup: Kill the children
    for my $pid (@children) {
        kill 9, $pid;
        waitpid($pid,0);
        delete $Global::unkilled_children{$pid};
    }
    # Cleanup: Unget the command_lines or the @args
    $Global::JobQueue->{'commandlinequeue'}->{'arg_queue'}->unget(@args);
    $Global::JobQueue->unget(@jobs);
    if($system_limit < $wanted_processes) {
	# The system_limit is less than the wanted_processes
	if($system_limit < 1 and not $Global::JobQueue->empty()) {
	    ::warning("Cannot spawn any jobs. Raising ulimit -u may help.\n");
	    ::wait_and_exit(255);
	}
	if(not $more_filehandles) {
	    ::warning("Only enough filehandles to run ", $system_limit,
		      " jobs in parallel. Raising ulimit -n may help.\n");
	}
	if($max_system_proc_reached) {
	    ::warning("Only enough available processes to run ", $system_limit,
		      " jobs in parallel. Raising ulimit -u may help.\n");
	}
    }
    if($Global::JobQueue->empty()) {
	$system_limit ||= 1;
    }
    if($self->string() ne ":" and
       $system_limit > $Global::default_simultaneous_sshlogins) {
        $system_limit =
            $self->simultaneous_sshlogin_limit($system_limit);
    }
    return $system_limit;
}

sub simultaneous_sshlogin_limit {
    # Test by logging in wanted number of times simultaneously
    # Returns:
    #   min($wanted_processes,$working_simultaneous_ssh_logins-1)
    my $self = shift;
    my $wanted_processes = shift;
    # Try twice because it guesses wrong sometimes
    # Choose the minimal
    my $ssh_limit =
        ::min($self->simultaneous_sshlogin($wanted_processes),
            $self->simultaneous_sshlogin($wanted_processes));
    if($ssh_limit < $wanted_processes) {
        my $serverlogin = $self->serverlogin();
        ::warning("ssh to $serverlogin only allows ",
		  "for $ssh_limit simultaneous logins.\n",
		  "You may raise this by changing ",
		  "/etc/ssh/sshd_config:MaxStartup on $serverlogin.\n",
		  "Using only ",$ssh_limit-1," connections ",
		  "to avoid race conditions.\n");
    }
    # Race condition can cause problem if using all sshs.
    if($ssh_limit > 1) { $ssh_limit -= 1; }
    return $ssh_limit;
}

sub simultaneous_sshlogin {
    # Using $sshlogin try to see if we can do $wanted_processes
    # simultaneous logins
    # (ssh host echo simultaneouslogin & ssh host echo simultaneouslogin & ...)|grep simul|wc -l
    # Returns:
    #   Number of succesful logins
    my $self = shift;
    my $wanted_processes = shift;
    my $sshcmd = $self->sshcommand();
    my $serverlogin = $self->serverlogin();
    my $cmd = "$sshcmd $serverlogin echo simultaneouslogin </dev/null 2>&1 &"x$wanted_processes;
    ::debug("Trying $wanted_processes logins at $serverlogin");
    open (SIMUL, "($cmd)|grep simultaneouslogin | wc -l|") or
	::die_bug("simultaneouslogin");
    my $ssh_limit = <SIMUL>;
    close SIMUL;
    chomp $ssh_limit;
    return $ssh_limit;
}

sub set_ncpus {
    my $self = shift;
    $self->{'ncpus'} = shift;
}

sub user_requested_processes {
    # Parse the number of processes that the user asked for using -j
    # Returns:
    #   the number of processes to run on this sshlogin
    my $self = shift;
    my $opt_P = shift;
    my $processes;
    if(defined $opt_P) {
        if($opt_P =~ /^\+(\d+)$/) {
            # E.g. -P +2
            my $j = $1;
            $processes =
                $self->ncpus() + $j;
        } elsif ($opt_P =~ /^-(\d+)$/) {
            # E.g. -P -2
            my $j = $1;
            $processes =
                $self->ncpus() - $j;
        } elsif ($opt_P =~ /^(\d+)\%$/) {
            my $j = $1;
            $processes =
                $self->ncpus() * $j / 100;
        } elsif ($opt_P =~ /^(\d+)$/) {
            $processes = $1;
            if($processes == 0) {
                # -P 0 = infinity (or at least close)
                $processes = $Global::infinity;
            }
        } elsif (-f $opt_P) {
            $Global::max_procs_file = $opt_P;
            $Global::max_procs_file_last_mod = (stat($Global::max_procs_file))[9];
            if(open(IN, $Global::max_procs_file)) {
                my $opt_P_file = join("",<IN>);
                close IN;
                $processes = $self->user_requested_processes($opt_P_file);
            } else {
                ::error("Cannot open $opt_P.\n");
                ::wait_and_exit(255);
            }
        } else {
            ::error("Parsing of --jobs/-j/--max-procs/-P failed.\n");
            ::die_usage();
        }
        if($processes < 1) {
            $processes = 1;
        }
    }
    return $processes;
}

sub ncpus {
    my $self = shift;
    if(not defined $self->{'ncpus'}) {
        my $sshcmd = $self->sshcommand();
        my $serverlogin = $self->serverlogin();
        if($serverlogin eq ":") {
            if($::opt_use_cpus_instead_of_cores) {
                $self->{'ncpus'} = no_of_cpus();
            } else {
                $self->{'ncpus'} = no_of_cores();
            }
        } else {
            my $ncpu;
            if($::opt_use_cpus_instead_of_cores) {
                $ncpu = qx(echo|$sshcmd $serverlogin parallel --number-of-cpus);
            } else {
                $ncpu = qx(echo|$sshcmd $serverlogin parallel --number-of-cores);
            }
	    chomp $ncpu;
            if($ncpu =~ /^\s*[0-9]+\s*$/s) {
                $self->{'ncpus'} = $ncpu;
            } else {
                ::warning("Could not figure out ",
			  "number of cpus on $serverlogin ($ncpu). Using 1.\n");
                $self->{'ncpus'} = 1;
            }
        }
    }
    return $self->{'ncpus'};
}

sub no_of_cpus {
    # Returns:
    #   Number of physical CPUs
    local $/="\n"; # If delimiter is set, then $/ will be wrong
    my $no_of_cpus;
    if ($^O eq 'linux') {
        $no_of_cpus = no_of_cpus_gnu_linux() || no_of_cores_gnu_linux();
    } elsif ($^O eq 'freebsd') {
        $no_of_cpus = no_of_cpus_freebsd();
    } elsif ($^O eq 'solaris') {
        $no_of_cpus = no_of_cpus_solaris();
    } elsif ($^O eq 'aix') {
        $no_of_cpus = no_of_cpus_aix();
    } elsif ($^O eq 'darwin') {
	$no_of_cpus = no_of_cpus_darwin();
    } else {
	$no_of_cpus = (no_of_cpus_freebsd()
		       || no_of_cpus_darwin()
		       || no_of_cpus_solaris()
		       || no_of_cpus_aix()
		       || no_of_cpus_gnu_linux()
	    );
    }
    if($no_of_cpus) {
	chomp $no_of_cpus;
        return $no_of_cpus;
    } else {
        ::warning("Cannot figure out number of cpus. Using 1.\n");
        return 1;
    }
}

sub no_of_cores {
    # Returns:
    #   Number of CPU cores
    local $/="\n"; # If delimiter is set, then $/ will be wrong
    my $no_of_cores;
    if ($^O eq 'linux') {
	$no_of_cores = no_of_cores_gnu_linux();
    } elsif ($^O eq 'freebsd') {
        $no_of_cores = no_of_cores_freebsd();
    } elsif ($^O eq 'solaris') {
	$no_of_cores = no_of_cores_solaris();
    } elsif ($^O eq 'aix') {
        $no_of_cores = no_of_cores_aix();
    } elsif ($^O eq 'darwin') {
	$no_of_cores = no_of_cores_darwin();
    } else {
	$no_of_cores = (no_of_cores_freebsd()
			|| no_of_cores_darwin()
			|| no_of_cores_solaris()
			|| no_of_cores_aix()
			|| no_of_cores_gnu_linux()
	    );
    }
    if($no_of_cores) {
	chomp $no_of_cores;
        return $no_of_cores;
    } else {
        ::warning("Cannot figure out number of CPU cores. Using 1.\n");
        return 1;
    }
}

sub no_of_cpus_gnu_linux {
    # Returns:
    #   Number of physical CPUs on GNU/Linux
    #   undef if not GNU/Linux
    my $no_of_cpus;
    if(-e "/proc/cpuinfo") {
        $no_of_cpus = 0;
        my %seen;
        open(IN,"cat /proc/cpuinfo|") || return undef;
        while(<IN>) {
            if(/^physical id.*[:](.*)/ and not $seen{$1}++) {
                $no_of_cpus++;
            }
        }
        close IN;
    }
    return $no_of_cpus;
}

sub no_of_cores_gnu_linux {
    # Returns:
    #   Number of CPU cores on GNU/Linux
    #   undef if not GNU/Linux
    my $no_of_cores;
    if(-e "/proc/cpuinfo") {
        $no_of_cores = 0;
        open(IN,"cat /proc/cpuinfo|") || return undef;
        while(<IN>) {
            /^processor.*[:]/ and $no_of_cores++;
        }
        close IN;
    }
    return $no_of_cores;
}

sub no_of_cpus_darwin {
    # Returns:
    #   Number of physical CPUs on Mac Darwin
    #   undef if not Mac Darwin
    my $no_of_cpus =
	(`sysctl -n hw.physicalcpu 2>/dev/null`
	 or
	 `sysctl -a hw 2>/dev/null | grep -w physicalcpu | awk '{ print \$2 }'`);
    return $no_of_cpus;
}

sub no_of_cores_darwin {
    # Returns:
    #   Number of CPU cores on Mac Darwin
    #   undef if not Mac Darwin
    my $no_of_cores =
	(`sysctl -n hw.logicalcpu 2>/dev/null`
	 or
	 `sysctl -a hw  2>/dev/null | grep -w logicalcpu | awk '{ print \$2 }'`);
    return $no_of_cores;
}

sub no_of_cpus_freebsd {
    # Returns:
    #   Number of physical CPUs on FreeBSD
    #   undef if not FreeBSD
    my $no_of_cpus =
	(`sysctl -a dev.cpu 2>/dev/null | grep \%parent | awk '{ print \$2 }' | uniq | wc -l | awk '{ print \$1 }'`
	 or
	 `sysctl hw.ncpu 2>/dev/null | awk '{ print \$2 }'`);
    chomp $no_of_cpus;
    return $no_of_cpus;
}

sub no_of_cores_freebsd {
    # Returns:
    #   Number of CPU cores on FreeBSD
    #   undef if not FreeBSD
    my $no_of_cores =
	(`sysctl hw.ncpu 2>/dev/null | awk '{ print \$2 }'`
	 or
	 `sysctl -a hw  2>/dev/null | grep -w logicalcpu | awk '{ print \$2 }'`);
    chomp $no_of_cores;
    return $no_of_cores;
}

sub no_of_cpus_solaris {
    # Returns:
    #   Number of physical CPUs on Solaris
    #   undef if not Solaris
    if(-x "/usr/sbin/psrinfo") {
        my @psrinfo = `/usr/sbin/psrinfo`;
        if($#psrinfo >= 0) {
            return $#psrinfo +1;
        }
    }
    if(-x "/usr/sbin/prtconf") {
        my @prtconf = `/usr/sbin/prtconf | grep cpu..instance`;
        if($#prtconf >= 0) {
            return $#prtconf +1;
        }
    }
    return undef;
}

sub no_of_cores_solaris {
    # Returns:
    #   Number of CPU cores on Solaris
    #   undef if not Solaris
    if(-x "/usr/sbin/psrinfo") {
        my @psrinfo = `/usr/sbin/psrinfo`;
        if($#psrinfo >= 0) {
            return $#psrinfo +1;
        }
    }
    if(-x "/usr/sbin/prtconf") {
        my @prtconf = `/usr/sbin/prtconf | grep cpu..instance`;
        if($#prtconf >= 0) {
            return $#prtconf +1;
        }
    }
    return undef;
}

sub no_of_cpus_aix {
    # Returns:
    #   Number of physical CPUs on AIX
    #   undef if not AIX
    my $no_of_cpus = 0;
    if(-x "/usr/sbin/lscfg") {
	open(IN,"/usr/sbin/lscfg -vs |grep proc | wc -l|tr -d ' ' |")
	    || return undef;
	$no_of_cpus = <IN>;
	chomp ($no_of_cpus);
	close IN;
    }
    return $no_of_cpus;
}

sub no_of_cores_aix {
    # Returns:
    #   Number of CPU cores on AIX
    #   undef if not AIX
    my $no_of_cores;
    if(-x "/usr/bin/vmstat") {
	open(IN,"/usr/bin/vmstat 1 1|") || return undef;
	while(<IN>) {
	    /lcpu=([0-9]*) / and $no_of_cores = $1;
	}
	close IN;
    }
    return $no_of_cores;
}

sub sshcommand {
    my $self = shift;
    if (not defined $self->{'sshcommand'}) {
        $self->sshcommand_of_sshlogin();
    }
    return $self->{'sshcommand'};
}

sub serverlogin {
    my $self = shift;
    if (not defined $self->{'serverlogin'}) {
        $self->sshcommand_of_sshlogin();
    }
    return $self->{'serverlogin'};
}

sub sshcommand_of_sshlogin {
    # 'server' -> ('ssh -S /tmp/parallel-ssh-RANDOM/host-','server')
    # 'user@server' -> ('ssh','user@server')
    # 'myssh user@server' -> ('myssh','user@server')
    # 'myssh -l user server' -> ('myssh -l user','server')
    # '/usr/bin/myssh -l user server' -> ('/usr/bin/myssh -l user','server')
    # Returns:
    #   sshcommand - defaults to 'ssh'
    #   login@host
    my $self = shift;
    my ($sshcmd, $serverlogin);
    if($self->{'string'} =~ /(.+) (\S+)$/) {
        # Own ssh command
        $sshcmd = $1; $serverlogin = $2;
    } else {
        # Normal ssh
        if($::opt_controlmaster) {
            # Use control_path to make ssh faster
            my $control_path = $self->control_path_dir()."/ssh-%r@%h:%p";
            $sshcmd = "ssh -S ".$control_path;
            $serverlogin = $self->{'string'};
            my $master = "ssh -MTS $control_path $serverlogin sleep 1";
            if(not $self->{'control_path'}{$control_path}++) {
                # Master is not running for this control_path
                # Start it
                my $pid = fork();
                if($pid) {
                    $Global::sshmaster{$pid}++;
                } else {
                    ::debug($master,"\n");
                    `$master </dev/null`;
                    ::wait_and_exit(0);
                }
            }
        } else {
            $sshcmd = "ssh"; $serverlogin = $self->{'string'};
        }
    }
    $self->{'sshcommand'} = $sshcmd;
    $self->{'serverlogin'} = $serverlogin;
}

sub control_path_dir {
    # Returns:
    #   path to directory
    my $self = shift;
    if(not defined $self->{'control_path_dir'}) {
        -e $ENV{'HOME'}."/.parallel" or mkdir $ENV{'HOME'}."/.parallel";
        -e $ENV{'HOME'}."/.parallel/tmp" or mkdir $ENV{'HOME'}."/.parallel/tmp";
        $self->{'control_path_dir'} =
	    File::Temp::tempdir($ENV{'HOME'}
				. "/.parallel/tmp/control_path_dir-XXXX",
				CLEANUP => 1);
    }
    return $self->{'control_path_dir'};
}


package JobQueue;

sub new {
    my $class = shift;
    my $command = shift;
    my $read_from = shift;
    my $context_replace = shift;
    my $max_number_of_args = shift;
    my $return_files = shift;
    my $commandlinequeue = CommandLineQueue->new(
        $command,$read_from,$context_replace,$max_number_of_args,$return_files);
    my @unget = ();
    return bless {
        'unget' => \@unget,
        'commandlinequeue' => $commandlinequeue,
        'total_jobs' => undef,
    }, ref($class) || $class;
}

sub get {
    my $self = shift;

    if(@{$self->{'unget'}}) {
        my $job = shift @{$self->{'unget'}};
        return ($job);
    } else {
        my $commandline = $self->{'commandlinequeue'}->get();
        if(defined $commandline) {
            my $job = Job->new($commandline);
            return $job;
        } else {
            return undef;
        }
    }
}

sub unget {
    my $self = shift;
    unshift @{$self->{'unget'}}, @_;
}

sub empty {
    my $self = shift;
    my $empty = (not @{$self->{'unget'}})
	&& $self->{'commandlinequeue'}->empty();
    ::debug("JobQueue->empty $empty\n");
    return $empty;
}

sub total_jobs {
    my $self = shift;
    if(not defined $self->{'total_jobs'}) {
        my $job;
        my @queue;
        while($job = $self->get()) {
            push @queue, $job;
        }
        $self->unget(@queue);
        $self->{'total_jobs'} = $#queue+1;
    }
    return $self->{'total_jobs'};
}

sub next_seq {
    my $self = shift;

    return $self->{'commandlinequeue'}->seq();
}

sub quote_args {
    my $self = shift;
    return $self->{'commandlinequeue'}->quote_args();
}


package Job;

sub new {
    my $class = shift;
    my $commandline = shift;
    return bless {
        'commandline' => $commandline, # The commandline with no args
        'workdir' => undef, # --workdir
        'stdin' => undef, # filehandle for stdin (used for --pipe)
        'stdout' => undef, # filehandle for stdout (used for --group)
	# filename for writing stdout to (used for --files)
        'stdoutfilename' => undef,
        'stderr' => undef, # filehandle for stderr (used for --group)
        'remaining' => "", # remaining data not sent to stdin (used for --pipe)
	'datawritten' => 0, # amount of data sent via stdin (used for --pipe)
        'transfersize' => 0, # size of files using --transfer
        'returnsize' => 0, # size of files using --return
        'pid' => undef,
        # hash of { SSHLogins => number of times the command failed there }
        'failed' => undef,
        'sshlogin' => undef,
        # The commandline wrapped with rsync and ssh
        'sshlogin_wrap' => undef,
        'exitstatus' => undef,
        'exitsignal' => undef,
	# Timestamp for timeout if any
	'timeout' => undef,
    }, ref($class) || $class;
}

sub replaced {
    my $self = shift;
    $self->{'commandline'} or Carp::croak("cmdline empty");
    return $self->{'commandline'}->replaced();
}

sub seq {
    my $self = shift;
    return $self->{'commandline'}->seq();
}

sub set_stdout {
    my $self = shift;
    $self->{'stdout'} = shift;
}

sub stdout {
    my $self = shift;
    return $self->{'stdout'};
}

sub set_stdoutfilename {
    my $self = shift;
    $self->{'stdoutfilename'} = shift;
}

sub stdoutfilename {
    my $self = shift;
    return $self->{'stdoutfilename'};
}

sub stderr {
    my $self = shift;
    return $self->{'stderr'};
}

sub set_stderr {
    my $self = shift;
    $self->{'stderr'} = shift;
}

sub stdin {
    my $self = shift;
    return $self->{'stdin'};
}

sub set_stdin {
    my $self = shift;
    my $stdin = shift;
    $self->{'stdin'} = $stdin;
}

sub write {
    my $self = shift;
    my $remaining_ref = shift;
    my $in = $self->{'stdin'};
    syswrite($in,$$remaining_ref);
}

sub pid {
    my $self = shift;
    return $self->{'pid'};
}

sub set_pid {
    my $self = shift;
    $self->{'pid'} = shift;
}

sub starttime {
    my $self = shift;
    return ((int(($self->{'starttime'})*1000))/1000);
}

sub set_starttime {
    my $self = shift;
    my $starttime = shift || ::hires_time();
    $self->{'starttime'} = $starttime;
}

sub runtime {
    my $self = shift;
    return ((int(($self->{'endtime'}-$self->{'starttime'})*1000))/1000);
}

sub endtime {
    my $self = shift;
    return $self->{'endtime'};
}

sub set_endtime {
    my $self = shift;
    my $endtime = shift || ::hires_time();
    $self->{'endtime'} = $endtime;
}


sub set_timeout {
    my $self = shift;
    my $delta_time = shift;
    $self->{'timeout'} = time + $delta_time;
}

sub timeout {
    my $self = shift;
    return $self->{'timeout'};
}

sub timedout {
    my $self = shift;
    return time > $self->{'timeout'};
}

sub kill {
    # kill the jobs
    my $self = shift;
    my @family_pids = $self->family_pids();
    # Record this jobs as failed
    $self->set_exitstatus(1);
    # Send two TERMs to give time to clean up
    for my $signal ("TERM", "TERM", "KILL") {
	my $alive = 0;
	for my $pid (@family_pids) {
	    if(kill 0, $pid) {
		# The job still running
		kill $signal, $pid;
		$alive = 1;
	    }
	}
	# Wait 200 ms between TERMs - but only if any pids are alive
	if($signal eq "TERM" and $alive) { ::usleep(200); }
    }
}

sub family_pids {
    # Find the pids with this->pid as (grand)*parent
    # TODO test this on different OS as 'ps' is known to be different
    my $self = shift;
    my $pid = $self->pid();
    my $script;
    if ($^O eq 'linux') {
	$script = q{
        family_pids() {
            for CHILDPID in `ps --ppid "$@" -o pid --no-headers`; do
                family_pids $CHILDPID &
            done
            echo "$@"
        }
        } .
	    "family_pids $pid; wait";
    } elsif ($^O eq 'solaris') {
	$script = q{
        family_pids() {
            if [ -z "$1" ] ; then return ; fi
            family_pids `pgrep -P "$*"` &
            for CHILDPID in "$@"; do
                echo $CHILDPID
            done
        }
        } .
	    "family_pids $pid; wait";
    } else {
	# This should cover all System V-derived flavors of 'ps'
	$script = q{
        family_pids() {
            for CHILDPID in `ps -f | awk '$3 == '"$@"' {print $2}'`; do
                family_pids $CHILDPID &
            done
            echo "$@"
        }
        } .
	    "family_pids $pid; wait";
    }
    my @pids = qx{$script};
    chomp(@pids);
    return (@pids);
}

sub failed {
    # return number of times failed for this $sshlogin
    my $self = shift;
    my $sshlogin = shift;
    return $self->{'failed'}{$sshlogin};
}

sub failed_here {
    # return number of times failed for the current $sshlogin
    my $self = shift;
    return $self->{'failed'}{$self->sshlogin()};
}

sub add_failed {
    # increase the number of times failed for this $sshlogin
    my $self = shift;
    my $sshlogin = shift;
    $self->{'failed'}{$sshlogin}++;
}

sub add_failed_here {
    # increase the number of times failed for the current $sshlogin
    my $self = shift;
    $self->{'failed'}{$self->sshlogin()}++;
}

sub reset_failed {
    # increase the number of times failed for this $sshlogin
    my $self = shift;
    my $sshlogin = shift;
    delete $self->{'failed'}{$sshlogin};
}

sub reset_failed_here {
    # increase the number of times failed for this $sshlogin
    my $self = shift;
    delete $self->{'failed'}{$self->sshlogin()};
}

sub min_failed {
    # Returns:
    #   the number of sshlogins this command has failed on
    #   the minimal number of times this command has failed
    my $self = shift;
    my $min_failures =
	::min(map { $self->{'failed'}{$_} }
		keys %{$self->{'failed'}});
    my $number_of_sshlogins_failed_on = scalar keys %{$self->{'failed'}};
    return ($number_of_sshlogins_failed_on,$min_failures);
}

sub total_failed {
    # Returns:
    #   the number of times this command has failed
    my $self = shift;
    my $total_failures = 0;
    for (values %{$self->{'failed'}}) {
	$total_failures += $_;
    }
    return ($total_failures);
}

sub set_sshlogin {
    my $self = shift;
    my $sshlogin = shift;
    $self->{'sshlogin'} = $sshlogin;
    delete $self->{'sshlogin_wrap'}; # If sshlogin is changed the wrap is wrong
}

sub sshlogin {
    my $self = shift;
    return $self->{'sshlogin'};
}

sub sshlogin_wrap {
    # Wrap the command with the commands needed to run remotely
    my $self = shift;
    if(not defined $self->{'sshlogin_wrap'}) {
	my $sshlogin = $self->sshlogin();
	my $sshcmd = $sshlogin->sshcommand();
	my $serverlogin = $sshlogin->serverlogin();
	my $next_command_line = $self->replaced();
	my ($pre,$post,$cleanup)=("","","");
	if($serverlogin eq ":") {
	    $self->{'sshlogin_wrap'} = $next_command_line;
	} else {
	    # --transfer
	    $pre .= $self->sshtransfer();
	    # --return
	    $post .= $self->sshreturn();
	    # --cleanup
	    $post .= $self->sshcleanup();
	    if($post) {
		# We need to save the exit status of the job
		$post = '_EXIT_status=$?; ' . $post . ' exit $_EXIT_status;';
	    }
	    # If the remote login shell is (t)csh then use 'setenv'
	    # otherwise use 'export'
	    my $parallel_env =
		q{'eval `echo $SHELL | grep -E "/(t)?csh" > /dev/null}
	    . q{ && echo setenv PARALLEL_SEQ '$PARALLEL_SEQ'\;}
	    . q{ setenv PARALLEL_PID '$PARALLEL_PID'}
	    . q{ || echo PARALLEL_SEQ='$PARALLEL_SEQ'\;export PARALLEL_SEQ\;}
	    . q{PARALLEL_PID='$PARALLEL_PID'\;export PARALLEL_PID` ;'};
	    if($::opt_workdir) {
		$self->{'sshlogin_wrap'} =
		    ($pre . "$sshcmd $serverlogin $parallel_env "
		     . ::shell_quote_scalar("cd ".$self->workdir()." && ")
		     . ::shell_quote_scalar($next_command_line).";".$post);
	    } else {
		$self->{'sshlogin_wrap'} =
		    ($pre . "$sshcmd $serverlogin $parallel_env "
		     . ::shell_quote_scalar($next_command_line).";".$post);
	    }
	}
    }
    return $self->{'sshlogin_wrap'};
}

sub transfer {
    # Files to transfer
    my $self = shift;
    my @transfer = ();
    $self->{'transfersize'} = 0;
    if($::opt_transfer) {
	for my $record (@{$self->{'commandline'}{'arg_list'}}) {
	    # Merge arguments from records into args
	    for my $arg (@$record) {
		CORE::push @transfer, $arg->orig();
		# filesize
		if(-e $arg->orig()) {
		    $self->{'transfersize'} += (stat($arg->orig()))[7];
		}
	    }
	}
    }
    return @transfer;
}

sub transfersize {
    my $self = shift;
    return $self->{'transfersize'};
}

sub sshtransfer {
    my $self = shift;
    my $sshlogin = $self->sshlogin();
    my $sshcmd = $sshlogin->sshcommand();
    my $serverlogin = $sshlogin->serverlogin();
    my $rsync_opt = "-rlDzR -e".::shell_quote_scalar($sshcmd);
    my $pre = "";
    for my $file ($self->transfer()) {
	$file =~ s:/\./:/:g; # Rsync treats /./ special. We dont want that
	$file =~ s:^\./::g; # Remove ./ if any
	my $relpath = ($file !~ m:^/:); # Is the path relative?
	# Use different subdirs depending on abs or rel path
	# Abs path: rsync -rlDzR /home/tange/dir/subdir/file.gz server:/
	# Rel path: rsync -rlDzR ./subdir/file.gz server:.parallel/tmp/tempid/
	# Rel path: rsync -rlDzR ./subdir/file.gz server:$workdir/
	my $remote_workdir = $self->workdir($file);
	my $rsync_destdir = ($relpath ? $remote_workdir : "/");
	if($relpath) {
	    $file = "./".$file;
	}
	if(-r $file) {
	    my $mkremote_workdir =
		$remote_workdir eq "." ? "true" :
		"$sshcmd $serverlogin mkdir -p $rsync_destdir";
	    $pre .= "$mkremote_workdir; rsync $rsync_opt "
		. ::shell_quote_scalar($file)." $serverlogin:$rsync_destdir;";
	} else {
	    ::warning($file, " is not readable and will not be transferred.\n");
	}
    }
    return $pre;
}

sub return {
    # Files to return
    # Quoted and with {...} substituted
    my $self = shift;
    my @return = ();
    for my $return (@{$self->{'commandline'}{'return_files'}}) {
	CORE::push @return,
	$self->{'commandline'}->replace_placeholders($return,1);
    }
    return @return;
}

sub returnsize {
    # This is called after the job has finished
    my $self = shift;
    for my $file ($self->return()) {
	if(-e $file) {
	    $self->{'returnsize'} += (stat($file))[7];
	}
    }
    return $self->{'returnsize'};
}

sub sshreturn {
    my $self = shift;
    my $sshlogin = $self->sshlogin();
    my $sshcmd = $sshlogin->sshcommand();
    my $serverlogin = $sshlogin->serverlogin();
    my $rsync_opt = "-rlDzR -e".::shell_quote_scalar($sshcmd);
    my $pre = "";
    for my $file ($self->return()) {
	$file =~ s:/\./:/:g; # Rsync treats /./ special. We dont want that
	$file =~ s:^\./::g; # Remove ./ if any
	my $relpath = ($file !~ m:^/:); # Is the path relative?
	# Use different subdirs depending on abs or rel path

	# Return or cleanup
	my @cmd = ();
	my $rsync_destdir = ($relpath ? "./" : "/");
	my $ret_file = $file;
	my $remove = $::opt_cleanup ? "--remove-source-files" : "";
	# If relative path: prepend workdir/./ to avoid problems
	# if the dir contains ':' and to get the right relative return path
	my $replaced = ($relpath ? $self->workdir()."/./" : "") . $file;
	# --return
	# Abs path: rsync -rlDzR server:/home/tange/dir/subdir/file.gz /
	# Rel path: rsync -rlDzR server:./subsir/file.gz ./
	$pre .= "rsync $rsync_opt $remove $serverlogin:".
	     ::shell_quote_scalar($replaced) . " ".$rsync_destdir.";";
    }
    return $pre;
}

sub sshcleanup {
    # Return the sshcommand needed to remove the file
    # Returns:
    #   ssh command needed to remove files from sshlogin
    my $self = shift;
    my $sshlogin = $self->sshlogin();
    my $sshcmd = $sshlogin->sshcommand();
    my $serverlogin = $sshlogin->serverlogin();
    my $workdir = $self->workdir();
    my $removeworkdir = "";
    my $cleancmd = "";

    for my $file ($self->cleanup()) {
	my @subworkdirs = parentdirs_of($file);
	$file = ::shell_quote_scalar($file);
	if(@subworkdirs) {
	    $removeworkdir = "; rmdir 2>/dev/null ".
		join(" ",map { ::shell_quote_scalar($workdir."/".$_) }
		     @subworkdirs);
	}
	my $relpath = ($file !~ m:^/:); # Is the path relative?
	my $cleandir = ($relpath ? $workdir."/" : "");
	$cleancmd .= "$sshcmd $serverlogin rm -f "
	    . ::shell_quote_scalar($cleandir.$file.$removeworkdir).";";
    }
    return $cleancmd;
}

sub cleanup {
    # Returns:
    #   Files to remove at cleanup
    my $self = shift;
    if($::opt_cleanup) {
	my @transfer = $self->transfer();
	return @transfer;
    } else {
	return ();
    }
}

sub workdir {
    # Returns:
    #   the workdir on a remote machine
    my $self = shift;
    if(not defined $self->{'workdir'}) {
	my $workdir;
	if(defined $::opt_workdir) {
	    if($::opt_workdir eq ".") {
		# . means current dir
		my $home = $ENV{'HOME'};
		eval 'use Cwd';
		my $cwd = cwd();
		$::opt_workdir = $cwd;
		if($home) {
		    # If homedir exists: remove the homedir from
		    # workdir if cwd starts with homedir
		    # E.g. /home/foo/my/dir => my/dir
		    # E.g. /tmp/my/dir => /tmp/my/dir
		    my ($home_dev, $home_ino) = (stat($home))[0,1];
		    my $parent = "";
		    my @dir_parts = split(m:/:,$cwd);
		    my $part;
		    while(defined ($part = shift @dir_parts)) {
			$part eq "" and next;
			$parent .= "/".$part;
			my ($parent_dev, $parent_ino) = (stat($parent))[0,1];
			if($parent_dev == $home_dev and $parent_ino == $home_ino) {
			    # dev and ino is the same: We found the homedir.
			    $::opt_workdir = join("/",@dir_parts);
			    last;
			}
		    }
		}
	    } elsif($::opt_workdir eq "...") {
		$workdir = ".parallel/tmp/" . ::hostname() . "-" . $$
		    . "-" . $self->seq();
	    } else {
		$workdir = $::opt_workdir;
		# Rsync treats /./ special. We dont want that
		$workdir =~ s:/\./:/:g; # Remove /./
		$workdir =~ s:/+$::; # Remove ending / if any
		$workdir =~ s:^\./::g; # Remove starting ./ if any
	    }
	} else {
	    $workdir = ".";
	}
	$self->{'workdir'} = $workdir;
    }
    return $self->{'workdir'};
}

sub parentdirs_of {
    # Return:
    #   all parentdirs except . of this dir or file - sorted desc by length
    my $d = shift;
    my @parents = ();
    while($d =~ s:/[^/]+$::) {
	if($d ne ".") {
	    push @parents, $d;
	}
    }
    return @parents;
}

sub start {
    # Setup STDOUT and STDERR for a job and start it.
    # Returns:
    #   job-object or undef if job not to run
    my $job = shift;
    my $command = $job->sshlogin_wrap();

    if($Global::interactive or $Global::stderr_verbose) {
	if($Global::interactive) {
	    print $Global::original_stderr "$command ?...";
	    open(TTY,"/dev/tty") || ::die_bug("interactive-tty");
	    my $answer = <TTY>;
	    close TTY;
	    my $run_yes = ($answer =~ /^\s*y/i);
	    if (not $run_yes) {
		$command = "true"; # Run the command 'true'
	    }
	} else {
	    print $Global::original_stderr "$command\n";
	}
    }

    local (*IN,*OUT,*ERR);
    my $pid;
    if($Global::grouped) {
	my ($outfh,$errfh,$name);
	# To group we create temporary files for STDOUT and STDERR
	# To avoid the cleanup unlink the files immediately (but keep them open)
	($outfh,$name) = ::tempfile(SUFFIX => ".par");
	$job->set_stdoutfilename($name);
	$::opt_files or unlink $name;
	($errfh,$name) = ::tempfile(SUFFIX => ".par");
	unlink $name;

	open OUT, '>&', $outfh or ::die_bug("Can't redirect STDOUT: $!");
	open ERR, '>&', $errfh or ::die_bug("Can't dup STDOUT: $!");
	$job->set_stdout($outfh);
	$job->set_stderr($errfh);
    } else {
	(*OUT,*ERR)=(*STDOUT,*STDERR);
    }

    if(($::opt_dryrun or $Global::verbose) and not $Global::grouped) {
	if($Global::verbose <= 1) {
	    print OUT $job->replaced(),"\n";
	} else {
	    # Verbose level > 1: Print the rsync and stuff
	    print OUT $command,"\n";
	}
    }
    if($::opt_dryrun) {
	$command = "true";
    }
    $ENV{'PARALLEL_SEQ'} = $job->seq();
    $ENV{'PARALLEL_PID'} = $$;
    ::debug("$Global::total_running processes. Starting ("
	    . $job->seq() . "): $command\n");
    if($::opt_pipe) {
	my ($in);
	# The eval is needed to catch exception from open3
	eval {
	    $pid = ::open3($in, ">&OUT", ">&ERR", $ENV{SHELL}, "-c", $command) ||
		::die_bug("open3-pipe");
	    1;
	};
	$job->set_stdin($in);
    } elsif(@::opt_a and not $Global::stdin_in_opt_a and $job->seq() == 1
	    and $job->sshlogin()->string() eq ":") {
	# Give STDIN to the first job if using -a (but only if running
	# locally - otherwise CTRL-C does not work for other jobs Bug#36585)
	*IN = *STDIN;
	# The eval is needed to catch exception from open3
	eval {
	    $pid = ::open3("<&IN", ">&OUT", ">&ERR", $ENV{SHELL}, "-c", $command) ||
		::die_bug("open3-a");
	    1;
	};
	# Re-open to avoid complaining
	open STDIN, "<&", $Global::original_stdin
	    or ::die_bug("dup-\$Global::original_stdin: $!");
    } elsif ($::opt_tty and not $Global::tty_taken and -c "/dev/tty" and
	     open(DEVTTY, "/dev/tty")) {
	# Give /dev/tty to the command if no one else is using it
	*IN = *DEVTTY;
	# The eval is needed to catch exception from open3
	eval {
	    $pid = ::open3("<&IN", ">&OUT", ">&ERR", $ENV{SHELL}, "-c", $command) ||
		::die_bug("open3-/dev/tty");
	    $Global::tty_taken = $pid;
	    close DEVTTY;
	    1;
	};
    } else {
	eval {
	    $pid = ::open3(::gensym, ">&OUT", ">&ERR", $ENV{SHELL}, "-c", $command) ||
		::die_bug("open3-gensym");
	    1;
	};
    }
    if($pid) {
	# A job was started
	$Global::total_running++;
	$Global::total_started++;
	$job->set_pid($pid);
	$job->set_starttime();
	if($::opt_timeout) {
	    # Timeout must be set before inserting into queue
	    $job->set_timeout($::opt_timeout);
	    $Global::timeoutq->insert($job);
	}
	return $job;
    } else {
	# No more processes
	::debug("Cannot spawn more jobs.\n");
	return undef;
    }
}

sub is_already_in_joblog {
    my $job = shift;
    return vec($Global::job_already_run,$job->seq(),1);
}

sub set_job_in_joblog {
    my $job = shift;
    vec($Global::job_already_run,$job->seq(),1) = 1;
}

sub should_be_retried {
    # Should this job be retried?
    # Returns
    #   0 - do not retry
    #   1 - job queued for retry
    my $self = shift;
    if (not $::opt_retries) {
	return 0;
    }
    if(not $self->exitstatus()) {
	# Completed with success. If there is a recorded failure: forget it
	$self->reset_failed_here();
	return 0
    } else {
	# The job failed. Should it be retried?
	$self->add_failed_here();
	if($self->total_failed() == $::opt_retries) {
	    # This has been retried enough
	    return 0;
	} else {
	    # This command should be retried
	    $Global::JobQueue->unget($self);
	    ::debug("Retry ".$self->seq()."\n");
	    return 1;
	}
    }
}

sub print {
    # Print the output of the jobs
    # Returns: N/A

    my $self = shift;
    ::debug(">>joboutput ".$self->replaced()."\n");
    # Only relevant for grouping
    $Global::grouped or return;
    my $out = $self->stdout();
    my $err = $self->stderr();
    my $command = $self->sshlogin_wrap();

    if($Global::joblog) {
	my $cmd;
	if($Global::verbose <= 1) {
	    $cmd = $self->replaced();
	} else {
	    # Verbose level > 1: Print the rsync and stuff
	    $cmd = $command;
	}
	printf $Global::joblog
	    join("\t", $self->seq(), $self->sshlogin()->string(),
		 $self->starttime(), $self->runtime(),
		 $self->transfersize(), $self->returnsize(),
		 $self->exitstatus(), $self->exitsignal(), $cmd
		 ). "\n";
	flush $Global::joblog;
	$self->set_job_in_joblog();
    }

    if(($::opt_dryrun or $Global::verbose) and $Global::grouped) {
	if($Global::verbose <= 1) {
	    print STDOUT $self->replaced(),"\n";
	} else {
	    # Verbose level > 1: Print the rsync and stuff
	    print STDOUT $command,"\n";
	}
	# If STDOUT and STDERR are merged,
	# we want the command to be printed first
	# so flush to avoid STDOUT being buffered
	flush STDOUT;
    }
    seek $err, 0, 0;
    if($Global::debug) {
	print STDERR "ERR:\n";
    }
    if($::opt_tag or defined $::opt_tagstring) {
	my $tag = $self->tag();
	while(<$err>) {
	    print STDERR $tag,$_;
	}
    } else {
	my $buf;
	while(sysread($err,$buf,1000_000)) {
	    print STDERR $buf;
	}
    }
    flush STDERR;

    if($::opt_files) {
	print STDOUT $self->{'stdoutfilename'},"\n";
    } else {
	my $buf;
	seek $out, 0, 0;
	if($Global::debug) {
	    print STDOUT "OUT:\n";
	}
	if($::opt_tag or defined $::opt_tagstring) {
	    my $tag = $self->tag();
	    while(<$out>) {
		print STDOUT $tag,$_;
	    }
	} else {
	    my $buf;
	    while(sysread($out,$buf,1000_000)) {
		print STDOUT $buf;
	    }
	}
	flush STDOUT;
	::debug("<<joboutput $command\n");
    }
    close $out;
    close $err;
}

sub tag {
    my $self = shift;
    if(not defined $self->{'tag'}) {
	$self->{'tag'} = $self->{'commandline'}->
	    replace_placeholders($::opt_tagstring,0)."\t";
    }
    return $self->{'tag'};
}

sub exitstatus {
    my $self = shift;
    return $self->{'exitstatus'};
}

sub set_exitstatus {
    my $self = shift;
    my $exitstatus = shift;
    if($exitstatus) {
	# Overwrite status if non-zero
	$self->{'exitstatus'} = $exitstatus;
    } else {
	# Set status but do not overwrite
	# Status may have been set by --timeout
	$self->{'exitstatus'} ||= $exitstatus;
    }
}

sub exitsignal {
    my $self = shift;
    return $self->{'exitsignal'};
}

sub set_exitsignal {
    my $self = shift;
    my $exitsignal = shift;
    $self->{'exitsignal'} = $exitsignal;
}


package CommandLine;

sub new {
    my $class = shift;
    my $seq = shift;
    my $command = ::undef_as_empty(shift);
    my $arg_queue = shift;
    my $context_replace = shift;
    my $max_number_of_args = shift; # for -N and normal (-N1)
    my $return_files = shift;
    my $len = {
	'{}' => 0, # Total length of all {} replaced with all args
	'{/}' => 0, # Total length of all {/} replaced with all args
	'{//}' => 0, # Total length of all {//} replaced with all args
	'{.}' => 0, # Total length of all {.} replaced with all args
	'{/.}' => 0, # Total length of all {/.} replaced with all args
	'no_args' => undef, # Length of command w/ all replacement args removed
	'context' => undef, # Length of context of an additional arg
    };
    my($sum,%replacecount);
    ($sum,$len->{'no_args'},$len->{'context'},$len->{'contextgroups'},
     %replacecount) = number_of_replacements($command,$context_replace);
    if($sum == 0) {
	if($command eq "") {
	    $command = $Global::replace{'{}'};
	} else {
	    # Add {} to the command if there are no {...}'s
	    $command .=" ".$Global::replace{'{}'};
        }
	($sum,$len->{'no_args'},$len->{'context'},$len->{'contextgroups'},
	 %replacecount) = number_of_replacements($command,$context_replace);
    }
    if(defined $::opt_tagstring) {
	my ($dummy1,$dummy2,$dummy3,$dummy4,%repcount) =
	    number_of_replacements($::opt_tagstring,$context_replace);
	# Merge %repcount with %replacecount to get the keys
	# for replacing replacement strings in $::opt_tagstring
	# The number, however, does not matter.
	for (keys %repcount) {
	    $replacecount{$_} ||= 0;
	}
    }

    my %positional_replace;
    my %multi_replace;
    for my $used (keys %replacecount) {
	if($used =~ /^{(\d+)(\D*)}$/) {
	    $positional_replace{$1} = '\{'.$2.'\}';
	} else {
	    $multi_replace{$used} = $used;
	}
    }
    return bless {
	'command' => $command,
	'seq' => $seq,
	'len' => $len,
	'arg_list' => [],
	'arg_queue' => $arg_queue,
	'max_number_of_args' => $max_number_of_args,
	'replacecount' => \%replacecount,
	'context_replace' => $context_replace,
	'return_files' => $return_files,
	'positional_replace' => \%positional_replace,
	'multi_replace' => \%multi_replace,
	'replaced' => undef,
    }, ref($class) || $class;
}

sub seq {
    my $self = shift;
    return $self->{'seq'};
}

sub populate {
    # Add arguments from arg_queue until the number of arguments or
    # max line length is reached
    my $self = shift;
    if($::opt_pipe) {
	# Do no read any args
	$self->push([Arg->new("")]);
	return;
    }
    my $next_arg;
    while (not $self->{'arg_queue'}->empty()) {
	$next_arg = $self->{'arg_queue'}->get();
	if(not defined $next_arg) {
	    next;
	}
	$self->push($next_arg);
	if($self->len() >= Limits::Command::max_length()) {
	    # TODO stuff about -x opt_x
	    if($self->number_of_args() > 1) {
		# There is something to work on
		$self->{'arg_queue'}->unget($self->pop());
		last;
	    } else {
		my $args = join(" ", map { $_->orig() } @$next_arg);
		print STDERR ("$Global::progname: Command line too ",
			      "long (", $self->len(), " >= ",
			      Limits::Command::max_length(),
			      ") at number ",
			      $self->{'arg_queue'}->arg_number(),
			      ": ".
			      (substr($args,0,50))."...\n");
		$self->{'arg_queue'}->unget($self->pop());
		::wait_and_exit(255);
	    }
	}

	if(defined $self->{'max_number_of_args'}) {
	    if($self->number_of_args() >= $self->{'max_number_of_args'}) {
		last;
	    }
	}
    }
    if(($::opt_m or $::opt_X) and not $CommandLine::already_spread
       and $self->{'arg_queue'}->empty() and $Global::max_jobs_running) {
	# -m or -X and EOF => Spread the arguments over all jobslots
	# (unless they are already spread)
	$CommandLine::already_spread++;
	if($self->number_of_args() > 1) {
	    $self->{'max_number_of_args'} =
		::ceil($self->number_of_args()/$Global::max_jobs_running);
	    $Global::JobQueue->{'commandlinequeue'}->{'max_number_of_args'} =
		$self->{'max_number_of_args'};
	    $self->{'arg_queue'}->unget($self->pop_all());
	    while($self->number_of_args() < $self->{'max_number_of_args'}) {
		$self->push($self->{'arg_queue'}->get());
	    }
	}
    }
}

sub push {
    # Add one or more records as arguments
    my $self = shift;
    my $record = shift;
    push @{$self->{'arg_list'}}, $record;
    #::my_dump($record);
    my $arg_no = ($self->number_of_args()-1) * ($#$record+1);

    for my $arg (@$record) {
	$arg_no++;
	if(defined $arg) {
	    if($self->{'positional_replace'}{$arg_no}) {
		# TODO probably bug here if both {1.} and {1} are used
		for my $used (keys %{$self->{'replacecount'}}) {
		    # {} {/} {//} {.} or {/.}
		    my $replacementfunction =
			$self->{'positional_replace'}{$arg_no};
		    # Find the single replacements
		    $self->{'len'}{$used} +=
			length $arg->replace($replacementfunction);
		}
	    }
	    for my $used (keys %{$self->{'multi_replace'}}) {
		# Add to the multireplacement
		$self->{'len'}{$used} += length $arg->replace($used);
	    }
	}
    }
}

sub pop {
    # Remove last argument
    my $self = shift;
    my $record = pop @{$self->{'arg_list'}};
    for my $arg (@$record) {
	if(defined $arg) {
	    for my $replacement_string (keys %{$self->{'replacecount'}}) {
		$self->{'len'}{$replacement_string} -=
		    length $arg->replace($replacement_string);
	    }
	}
    }
    return $record;
}

sub pop_all {
    # Remove all arguments
    my $self = shift;
    my @popped = @{$self->{'arg_list'}};
    for my $replacement_string (keys %{$self->{'replacecount'}}) {
	$self->{'len'}{$replacement_string} = 0;
    }
    $self->{'arg_list'} = [];
    return @popped;
}

sub number_of_args {
    my $self = shift;
    # This is really number of records
    return $#{$self->{'arg_list'}}+1;
}

sub args_as_string {
    # Returns:
    #  all unmodified arguments joined with ' ' (similar to {})
    my $self = shift;
    return (join " ", map { $_->orig() }
	    map { @$_ } @{$self->{'arg_list'}});
}

sub len {
    # The length of the command line with args substituted
    my $self = shift;
    my $len = 0;
    # Add length of the original command with no args
    $len += $self->{'len'}{'no_args'};
    if($self->{'context_replace'}) {
	$len += $self->number_of_args()*$self->{'len'}{'context'};
	for my $replstring (keys %{$self->{'replacecount'}}) {
	    if(defined $self->{'len'}{$replstring}) {
		$len += $self->{'len'}{$replstring} *
		    $self->{'replacecount'}{$replstring};
	    }
	}
	$len += ($self->number_of_args()-1) * $self->{'len'}{'contextgroups'};
    } else {
	# Each replacement string may occur several times
	# Add the length for each time
	for my $replstring (keys %{$self->{'replacecount'}}) {
	    if(defined $self->{'len'}{$replstring}) {
		$len += $self->{'len'}{$replstring} *
		    $self->{'replacecount'}{$replstring};
	    }
	    if($Global::replace{$replstring}) {
		# This is a multi replacestring ({} {/} {//} {.} {/.})
		# Add each space between two arguments
		my $number_of_args = ($#{$self->{'arg_list'}[0]}+1) *
		    $self->number_of_args();
		$len += ($number_of_args-1) *
		    $self->{'replacecount'}{$replstring};
	    }
	}
    }
    if($::opt_nice) {
	# Pessimistic length if --nice is set
	# Worse than worst case: every char needs to be quoted with \
	$len *= 2;
    }
    if($::opt_shellquote) {
	# Pessimistic length if --shellquote is set
	# Worse than worst case: every char needs to be quoted with \ twice
	$len *= 4;
    }
    return $len;
}

sub multi_regexp {
    if(not $CommandLine::multi_regexp) {
	$CommandLine::multi_regexp =
	"(?:".
	join("|",map {my $a=$_; $a =~ s/(\W)/\\$1/g; $a}
	     ($Global::replace{"{}"},
	      $Global::replace{"{.}"},
	      $Global::replace{"{/}"},
	      $Global::replace{"{//}"},
	      $Global::replace{"{/.}"})
	).")";
    }
    return $CommandLine::multi_regexp;
}

sub number_of_replacements {
    # Returns:
    #  sum_of_count, length_of_command_with_no_args,
    #  length_of_context { 'replacementstring' => count }
    my $command = shift;
    my $context_replace = shift;
    my %count = ();
    my $sum = 0;
    my $cmd = $command;
    my $multi_regexp = multi_regexp();
    my $replacement_regexp =
	"(?:". ::maybe_quote('\{') .
	'\d+(?:|\.|/\.|/|//)?' . # {n} {n.} {n/.} {n/} {n//}
	::maybe_quote('\}') .
	'|'.
	join("|",map {$a=$_;$a=~s/(\W)/\\$1/g; $a} values %Global::replace).
	")";
    my %c = ();
    $cmd =~ s/($replacement_regexp)/$c{$1}++;"\0"/ogex;
    for my $k (keys %c) {
	if(defined $Global::replace_rev{$k}) {
	    $count{$Global::replace_rev{$k}} = $c{$k};
	} else {
	    $count{::maybe_unquote($k)} = $c{$k};
	}
	$sum += $c{$k};
    }
    my $number_of_context_groups = 0;
    my $no_args;
    my $context;
    if($context_replace) {
	$cmd = $command;
	while($cmd =~ s/\S*$multi_regexp\S*//o) {
	    $number_of_context_groups++;
	}
	$no_args = length $cmd;
	$context = length($command) - $no_args;
    } else {
	$cmd = $command;
	$cmd =~ s/$multi_regexp//go;
	$cmd =~ s/$replacement_regexp//go;
	$no_args = length($cmd);
	$context = length($command) - $no_args;
    }
    for my $k (keys %count) {
	if(defined $Global::replace{$k}) {
	    # {} {/} {//} {.} {/.} {#}
	    $context -= (length $Global::replace{$k}) * $count{$k};
	} else {
	    # {n}
	    $context -= (length $k) * $count{$k};
	}
    }
    return ($sum,$no_args,$context,$number_of_context_groups,%count);
}

sub replaced {
    my $self = shift;
    if(not defined $self->{'replaced'}) {
	$self->{'replaced'} = $self->replace_placeholders($self->{'command'},0);
	if($self->{'replaced'} =~ /^\s*(-\S+)/) {
	    # Is this really a command in $PATH starting with '-'?
	    my $cmd = $1;
	    if(not grep { -e $_."/".$cmd } split(":",$ENV{'PATH'})) {
		::error("Command ($cmd) starts with '-'. Is this a wrong option?.\n");
		::wait_and_exit(255);
	    }
	}
	if($::opt_nice) {
	    # Prepend nice -n19 $SHELL -c
	    # and quote
	    $self->{'replaced'} = nice() ." -n" . $::opt_nice . " "
		. $ENV{SHELL}." -c "
		. ::shell_quote_scalar($self->{'replaced'});
	}
	if($::opt_shellquote) {
	    # Prepend echo
	    # and quote twice
	    $self->{'replaced'} = "echo " .
		::shell_quote_scalar(::shell_quote_scalar($self->{'replaced'}));
	}
    }
    if($::oodebug and length($self->{'replaced'}) != ($self->len())) {
	::my_dump($self);
	Carp::cluck("replaced len=" . length($self->{'replaced'})
		    . " computed=" . ($self->len()));
    }
    return $self->{'replaced'};
}

sub nice {
    # Returns:
    #   path to nice
    # Needed because tcsh's built-in nice does not support 'nice -n19'
    if(not $Global::path_to_nice) {
	$Global::path_to_nice = "nice";
	for my $n ((split/:/, $ENV{'PATH'}), "/bin", "/usr/bin") {
	    if(-x $n."/nice") {
		$Global::path_to_nice = $n."/nice";
		last;
	    }
	}
    }
    return $Global::path_to_nice;
}

sub replace_placeholders {
    my $self = shift;
    my $target = shift;
    my $quoteall = shift;
    my $context_replace = $self->{'context_replace'};
    my $replaced;

    if($self->{'context_replace'}) {
	$replaced = $self->context_replace_placeholders($target,$quoteall);
    } else {
	$replaced = $self->simple_replace_placeholders($target,$quoteall);
    }
    return $replaced;
}

sub context_replace_placeholders {
    my $self = shift;
    my $target = shift;
    my $quoteall = shift;
    # -X = context replace
    # maybe multiple input sources
    # maybe --xapply
    # $self->{'arg_list'} = [ [Arg11, Arg12], [Arg21, Arg22], [Arg31, Arg32] ]

    my @args=();
    my @used_multi;
    my %replace;

    for my $record (@{$self->{'arg_list'}}) {
	# Merge arguments from records into args for easy access
	CORE::push @args, @$record;
    }

    # Replacement functions
    my @rep = qw({} {/} {//} {.} {/.});
    # Inner part of replacement functions
    my @rep_inner = ('', '/', '//', '.', '/.');
    # Regexp for replacement functions
    my $rep_regexp = "(?:". join('|', map { $_=~s/(\W)/\\$1/g; $_} @rep) . ")";
    # Regexp for inner replacement functions
    my $rep_inner_regexp = "(?:". join('|', map { $_=~s/(\W)/\\$1/g; $_} @rep_inner) . ")";
    # Seq replace string: {#}
    my $rep_seq_regexp = '(?:'.::maybe_quote('\{\#\}').")";
    # Normal replace strings
    my $rep_str_regexp = multi_regexp();
    # Positional replace strings
    my $rep_str_pos_regexp = ::maybe_quote('\{').'\d+'.$rep_inner_regexp.::maybe_quote('\}');

    # Fish out the words that have replacement strings in them
    my $tt = $target;
    my %word;
    while($tt =~ s/(\S*(?:$rep_str_regexp|$rep_str_pos_regexp|$rep_seq_regexp)\S*)/\0/o) {
	$word{$1}++;
    }
    # For each word: Generate the replacement string for that word.
    for my $origword (keys %word) {
	my @pos_replacements=();
	my @replacements=();
	my $w;
	my $word = $origword; # Make a local modifyable copy

	# replace {#} if it exists
	$word =~ s/$rep_seq_regexp/$self->seq()/geo;
	if($word =~ /$rep_str_pos_regexp/o) {
	    # There are positional replacement strings
	    my @argset;
	    if($#{$self->{'arg_list'}->[0]} == 0) {
		# Only one input source: Treat it as a set
		@argset = [ @args ];
	    } else {
		@argset = @{$self->{'arg_list'}};
	    }
	    # Match 1..n where n = max args in a argset
	    my $pos_regexp = "(?:".join("|", 1 .. $#{$argset[0]}+1).")";
	    my $pos_inner_regexp = ::maybe_quote('\{') .
		"($pos_regexp)($rep_inner_regexp)" .
		::maybe_quote('\}');
	    for my $argset (@argset) {
		# Replace all positional arguments - e.g. {7/.}
		# with the replacement function - e.g. {/.}
		# of that argument
		if(defined $self->{'max_number_of_args'}) {
		    # Fill up if we have a half completed line, so {n} will be empty
		    while($#$argset < $self->{'max_number_of_args'}) {
			CORE::push @$argset, Arg->new("");
		    }
		}
		$w = $word;
		$w =~ s/$pos_inner_regexp/$argset->[$1-1]->replace('{'.$2.'}')/geo;
		CORE::push @pos_replacements, $w;
	    }
	}
	if(not @pos_replacements) {
	    @pos_replacements = ($word);
	}

	if($word =~ m:$rep_str_regexp:) {
	    # There are normal replacement strings
	    for my $w (@pos_replacements) {
		for my $arg (@args) {
		    my $wmulti = $w;
		    $wmulti =~ s/($rep_str_regexp)/$arg->replace($Global::replace_rev{$1})/geo;
		    CORE::push @replacements, $wmulti;
		}
	    }
	}
	if(@replacements) {
	    CORE::push @{$replace{$origword}}, @replacements;
	} else {
	    CORE::push @{$replace{$origword}}, @pos_replacements;
	}
    }
    # Substitute the replace strings with the replacement values
    # Must be sorted by length if a short word is a substring of a long word
    my $regexp = join('|', map { $_=~s/(\W)/\\$1/g; $_}
		      sort { length $b <=> length $a } keys %word);
    $target =~ s/($regexp)/join(" ",@{$replace{$1}})/ge;
    return $target;
}

sub simple_replace_placeholders {
    # no context (no -X)
    # maybe multiple input sources
    # maybe --xapply
    my $self = shift;
    my $target = shift;
    my $quoteall = shift;
    my @args=();
    my @used_multi;
    my %replace;

    for my $record (@{$self->{'arg_list'}}) {
	# Merge arguments from records into args for easy access
	CORE::push @args, @$record;
    }
    # Which replace strings are used?
    # {#} {} {/} {//} {.} {/.} {n} {n/} {n//} {n.} {n/.}
    for my $used (keys %{$self->{'replacecount'}}) {
	# What are the replacement values for the replace strings?
	if(grep { $used eq $_ } qw({} {/} {//} {.} {/.})) {
	    # {} {/} {//} {.} {/.}
	    $replace{$Global::replace{$used}} =
		join(" ", map { $_->replace($used) } @args);
	} elsif($used =~ /^\{(\d+)(|\/|\/\/|\.|\/\.)\}$/) {
	    # {n} {n/} {n//} {n.} {n/.}
	    my $positional = $1; # number if any
	    my $replacementfunction = "{".::undef_as_empty($2)."}"; # {} {/} {//} {.} or {/.}
	    # If -q then the replacementstrings will be quoted, too
	    # {1.} -> \{1.\}
	    $Global::replace{$used} ||= ::maybe_quote($used);
	    if(defined $args[$positional-1]) {
		# we have a matching argument for {n}
		$replace{$Global::replace{$used}} =
		    $args[$positional-1]->replace($replacementfunction);
	    } else {
		if($positional <= $self->{'max_number_of_args'}) {
		    # Fill up if we have a half completed line
		    $replace{$Global::replace{$used}} = "";
		}
	    }
	} elsif($used eq "{#}") {
	    # {#}
	    $replace{$Global::replace{$used}} = $self->seq();
	} else {
	    ::die_bug('simple_replace_placeholders_20110530');
	}
    }
    # Substitute the replace strings with the replacement values
    my $regexp = join('|', map { $_=~s/(\W)/\\$1/g; $_} keys %replace);
    if($regexp) {
	if($quoteall) {
	    # This is for --return: The whole expression must be
	    # quoted - not just the replacements
	    %replace = map { $_ => ::shell_unquote($replace{$_}) } keys %replace;
	    $target =~ s/($regexp)/$replace{$1}/g;
	    $target = ::shell_quote_scalar($target);
	} else {
	    $target =~ s/($regexp)/$replace{$1}/g;
	}
    }
    return $target;
}


package CommandLineQueue;

sub new {
    my $class = shift;
    my $command = shift;
    my $read_from = shift;
    my $context_replace = shift;
    my $max_number_of_args = shift;
    my $return_files = shift;
    my @unget = ();
    return bless {
	'unget' => \@unget,
	'command' => $command,
	'arg_queue' => RecordQueue->new($read_from,$::opt_colsep),
	'context_replace' => $context_replace,
	'max_number_of_args' => $max_number_of_args,
	'size' => undef,
	'return_files' => $return_files,
	'seq' => 1,
    }, ref($class) || $class;
}

sub get {
    my $self = shift;
    if(@{$self->{'unget'}}) {
	my $cmd_line = shift @{$self->{'unget'}};
	return ($cmd_line);
    } else {
	my $cmd_line;
	$cmd_line = CommandLine->new($self->seq(),
				     $self->{'command'},
				     $self->{'arg_queue'},
				     $self->{'context_replace'},
				     $self->{'max_number_of_args'},
				     $self->{'return_files'},
	    );
	$cmd_line->populate();
	::debug("cmd_line->number_of_args ".$cmd_line->number_of_args()."\n");
	if($::opt_pipe) {
	    if($cmd_line->replaced() eq "") {
		# Empty command - pipe requires a command
		::error("--pipe must have a command to pipe into (e.g. 'cat').\n");
		::wait_and_exit(255);
	    }
	} else {
	    if($cmd_line->number_of_args() == 0) {
		# We did not get more args - maybe at EOF string?
		return undef;
	    } elsif($cmd_line->replaced() eq "") {
		# Empty command - get the next instead
		return $self->get();
	    }
	}
	$self->set_seq($self->seq()+1);
	return $cmd_line;
    }
}

sub unget {
    my $self = shift;
    unshift @{$self->{'unget'}}, @_;
}

sub empty {
    my $self = shift;
    my $empty = (not @{$self->{'unget'}}) && $self->{'arg_queue'}->empty();
    ::debug("CommandLineQueue->empty $empty\n");
    return $empty;
}

sub seq {
    my $self = shift;
    return $self->{'seq'};
}

sub set_seq {
    my $self = shift;
    $self->{'seq'} = shift;
}

sub quote_args {
    my $self = shift;
    # If there is not command emulate |bash
    return $self->{'command'};
}

sub size {
    my $self = shift;
    if(not $self->{'size'}) {
	my @all_lines = ();
	while(not $self->{'arg_queue'}->empty()) {
	    push @all_lines, CommandLine->new($self->{'command'},
					      $self->{'arg_queue'},
					      $self->{'context_replace'},
					      $self->{'max_number_of_args'});
	}
	$self->{'size'} = @all_lines;
	$self->unget(@all_lines);
    }
    return $self->{'size'};
}


package Limits::Command;

# Maximal command line length (for -m and -X)
sub max_length {
    # Find the max_length of a command line and cache it
    # Returns:
    #   number of chars on the longest command line allowed
    if(not $Limits::Command::line_max_len) {
	if($::opt_s) {
	    if(is_acceptable_command_line_length($::opt_s)) {
		$Limits::Command::line_max_len = $::opt_s;
	    } else {
		# -s is too long: Find the correct
		$Limits::Command::line_max_len = binary_find_max_length(0,$::opt_s);
	    }
	    if($::opt_s <= $Limits::Command::line_max_len) {
		$Limits::Command::line_max_len = $::opt_s;
	    } else {
		::warning("Value for -s option ",
			  "should be < $Limits::Command::line_max_len.\n");
	    }
	} else {
	    $Limits::Command::line_max_len = real_max_length();
	}
    }
    return $Limits::Command::line_max_len;
}

sub real_max_length {
    # Find the max_length of a command line
    # Returns:
    #   The maximal command line length
    # Use an upper bound of 8 MB if the shell allows for for infinite long lengths
    my $upper = 8_000_000;
    my $len = 8;
    do {
	if($len > $upper) { return $len };
	$len *= 16;
    } while (is_acceptable_command_line_length($len));
    # Then search for the actual max length between 0 and upper bound
    return binary_find_max_length(int($len/16),$len);
}

sub binary_find_max_length {
    # Given a lower and upper bound find the max_length of a command line
    # Returns:
    #   number of chars on the longest command line allowed
    my ($lower, $upper) = (@_);
    if($lower == $upper or $lower == $upper-1) { return $lower; }
    my $middle = int (($upper-$lower)/2 + $lower);
    ::debug("Maxlen: $lower,$upper,$middle\n");
    if (is_acceptable_command_line_length($middle)) {
	return binary_find_max_length($middle,$upper);
    } else {
	return binary_find_max_length($lower,$middle);
    }
}

sub is_acceptable_command_line_length {
    # Test if a command line of this length can run
    # Returns:
    #   0 if the command line length is too long
    #   1 otherwise
    my $len = shift;

    $CommandMaxLength::is_acceptable_command_line_length++;
    ::debug("$CommandMaxLength::is_acceptable_command_line_length $len\n");
    local *STDERR;
    open (STDERR,">/dev/null");
    system "true "."x"x$len;
    close STDERR;
    ::debug("$len $?\n");
    return not $?;
}


package RecordQueue;

sub new {
    my $class = shift;
    my $fhs = shift;
    my $colsep = shift;
    my @unget = ();
    my $arg_sub_queue;
    if($colsep) {
	# Open one file with colsep
	$arg_sub_queue = RecordColQueue->new($fhs);
    } else {
	# Open one or more files if multiple -a
	$arg_sub_queue = MultifileQueue->new($fhs);
    }
    return bless {
	'unget' => \@unget,
	'arg_number' => 0,
	'arg_sub_queue' => $arg_sub_queue,
    }, ref($class) || $class;
}

sub get {
    # Returns:
    #   reference to array of Arg-objects
    my $self = shift;
    if(@{$self->{'unget'}}) {
	return shift @{$self->{'unget'}};
    }
    $self->{'arg_number'}++;
    my $ret = $self->{'arg_sub_queue'}->get();
    if(defined $Global::max_number_of_args
       and $Global::max_number_of_args == 0) {
	::debug("Read 1 but return 0 args\n");
	return [Arg->new("")];
    } else {
	return $ret;
    }
}

sub unget {
    my $self = shift;
    ::debug("RecordQueue-unget '@_'\n");
    $self->{'arg_number'}--;
    unshift @{$self->{'unget'}}, @_;
}

sub empty {
    my $self = shift;
    my $empty = not @{$self->{'unget'}};
    $empty &&= $self->{'arg_sub_queue'}->empty();
    ::debug("RecordQueue->empty $empty\n");
    return $empty;
}

sub arg_number {
    my $self = shift;
    return $self->{'arg_number'};
}


package RecordColQueue;

sub new {
    my $class = shift;
    my $fhs = shift;
    my @unget = ();
    my $arg_sub_queue = MultifileQueue->new($fhs);
    return bless {
	'unget' => \@unget,
	'arg_sub_queue' => $arg_sub_queue,
    }, ref($class) || $class;
}

sub get {
    # Returns:
    #   reference to array of Arg-objects
    my $self = shift;
    if(@{$self->{'unget'}}) {
	return shift @{$self->{'unget'}};
    }
    my $unget_ref=$self->{'unget'};
    if($self->{'arg_sub_queue'}->empty()) {
	return undef;
    }
    my $in_record = $self->{'arg_sub_queue'}->get();
    if(defined $in_record) {
	my @out_record = ();
	for my $arg (@$in_record) {
	    ::debug("RecordColQueue::arg $arg\n");
	    my $line = $arg->orig();
	    ::debug("line='$line'\n");
	    if($line ne "") {
		for my $s (split /$::opt_colsep/o, $line, -1) {
		    push @out_record, Arg->new($s);
		}
	    } else {
		push @out_record, Arg->new("");
	    }
	}
	return \@out_record;
    } else {
	return undef;
    }
}

sub unget {
    my $self = shift;
    ::debug("RecordColQueue-unget '@_'\n");
    unshift @{$self->{'unget'}}, @_;
}

sub empty {
    my $self = shift;
    my $empty = (not @{$self->{'unget'}} and $self->{'arg_sub_queue'}->empty());
    ::debug("RecordColQueue->empty $empty");
    return $empty;
}


package MultifileQueue;

@Global::unget_argv=();

sub new {
    my $class = shift;
    my $fhs = shift;
    for my $fh (@$fhs) {
	if(-t $fh) {
	    ::warning("Input is read from the terminal. ".
		      "Only experts do this on purpose. ".
		      "Press CTRL-D to exit.\n");
	}
    }
    return bless {
	'unget' => \@Global::unget_argv,
	'fhs' => $fhs,
	'arg_matrix' => undef,
    }, ref($class) || $class;
}

sub get {
    my $self = shift;
    if($::opt_xapply) {
	return $self->xapply_get();
    } else {
	return $self->nest_get();
    }
}

sub unget {
    my $self = shift;
    ::debug("MultifileQueue-unget '@_'\n");
    unshift @{$self->{'unget'}}, @_;
}

sub empty {
    my $self = shift;
    my $empty = (not @Global::unget_argv
		 and not @{$self->{'unget'}});
    for my $fh (@{$self->{'fhs'}}) {
	$empty &&= eof($fh);
    }
    ::debug("MultifileQueue->empty $empty\n");
    return $empty;
}

sub xapply_get {
    my $self = shift;
    if(@{$self->{'unget'}}) {
	return shift @{$self->{'unget'}};
    }
    my @record = ();
    my $prepend = undef;
    my $empty = 1;
    for my $fh (@{$self->{'fhs'}}) {
	my $arg = read_arg_from_fh($fh);
	if(defined $arg) {
	    push @record, $arg;
	    $empty = 0;
	} else {
	    push @record, Arg->new("");
	}
    }
    if($empty) {
	return undef;
    } else {
	return \@record;
    }
}

sub nest_get {
    my $self = shift;
    if(@{$self->{'unget'}}) {
	return shift @{$self->{'unget'}};
    }
    my @record = ();
    my $prepend = undef;
    my $empty = 1;
    my $no_of_inputsources = $#{$self->{'fhs'}} + 1;
    if(not $self->{'arg_matrix'}) {
	# Initialize @arg_matrix with one arg from each file
	# read one line from each file
	my @first_arg_set;
	my $all_empty = 1;
	for (my $fhno = 0; $fhno < $no_of_inputsources ; $fhno++) {
	    my $arg = read_arg_from_fh($self->{'fhs'}[$fhno]);
	    if(defined $arg) {
		$all_empty = 0;
	    }
	    $self->{'arg_matrix'}[$fhno][0] = $arg || Arg->new("");
	    push @first_arg_set, $self->{'arg_matrix'}[$fhno][0];
	}
	if($all_empty) {
	    # All filehandles were at eof or eof-string
	    return undef;
	}
	return [@first_arg_set];
    }

    # Treat the case with one input source special.  For multiple
    # input sources we need to remember all previously read values to
    # generate all combinations. But for one input source we can
    # forget the value after first use.
    if($no_of_inputsources == 1) {
	my $arg = read_arg_from_fh($self->{'fhs'}[0]);
	if(defined($arg)) {
	    return [$arg];
	}
	return undef;
    }
    for (my $fhno = $no_of_inputsources - 1; $fhno >= 0; $fhno--) {
	if(eof($self->{'fhs'}[$fhno])) {
	    next;
	} else {
	    # read one
	    my $arg = read_arg_from_fh($self->{'fhs'}[$fhno]);
	    defined($arg) || next; # If we just read an EOF string: Treat this as EOF
	    my $len = $#{$self->{'arg_matrix'}[$fhno]} + 1;
	    $self->{'arg_matrix'}[$fhno][$len] = $arg;
	    # make all new combinations
	    my @combarg = ();
	    for (my $fhn = 0; $fhn < $no_of_inputsources; $fhn++) {
		push @combarg, [0, $#{$self->{'arg_matrix'}[$fhn]}];
	    }
	    $combarg[$fhno] = [$len,$len]; # Find only combinations with this new entry
	    # map combinations
	    # [ 1, 3, 7 ], [ 2, 4, 1 ]
	    # =>
	    # [ m[0][1], m[1][3], m[3][7] ], [ m[0][2], m[1][4], m[2][1] ]
	    my @mapped;
	    for my $c (expand_combinations(@combarg)) {
		my @a;
		for my $n (0 .. $no_of_inputsources - 1 ) {
		    push @a,  $self->{'arg_matrix'}[$n][$$c[$n]];
		}
		push @mapped, \@a;
	    }
	    # append the mapped to the ungotten arguments
	    push @{$self->{'unget'}}, @mapped;
	    # get the first
	    return shift @{$self->{'unget'}};
	}
    }
    # all are eof or at EOF string; return from the unget queue
    return shift @{$self->{'unget'}};
}

sub read_arg_from_fh {
    # Read one Arg from filehandle
    # Returns:
    #   Arg-object with one read line
    #   undef if end of file
    my $fh = shift;
    my $prepend = undef;
    my $arg;
    do {{
	if(eof($fh)) {
	    if(defined $prepend) {
		return Arg->new($prepend);
	    } else {
		return undef;
	    }
	}
	$arg = <$fh>;
	::debug("read $arg\n");
	# Remove delimiter
	$arg =~ s:$/$::;
	if($Global::end_of_file_string and
	   $arg eq $Global::end_of_file_string) {
	    # Ignore the rest of input file
	    while (<$fh>) {}
	    ::debug("EOF-string $arg\n");
	    if(defined $prepend) {
		return Arg->new($prepend);
	    } else {
		return undef;
	    }
	}
	if(defined $prepend) {
	    $arg = $prepend.$arg; # For line continuation
	    $prepend = undef; #undef;
	}
	if($Global::ignore_empty) {
	    if($arg =~ /^\s*$/) {
		redo; # Try the next line
	    }
	}
	if($Global::max_lines) {
	    if($arg =~ /\s$/) {
		# Trailing space => continued on next line
		$prepend = $arg;
		redo;
	    }
	}
    }} while (1 == 0); # Dummy loop for redo
    if(defined $arg) {
	return Arg->new($arg);
    } else {
	::die_bug("multiread arg undefined");
    }
}

sub expand_combinations {
    # Input:
    #   ([xmin,xmax], [ymin,ymax], ...)
    # Returns ([x,y,...],[x,y,...])
    # where xmin <= x <= xmax and ymin <= y <= ymax
    my $minmax_ref = shift;
    my $xmin = $$minmax_ref[0];
    my $xmax = $$minmax_ref[1];
    my @p;
    if(@_) {
	# If there are more columns: Compute those recursively
	my @rest = expand_combinations(@_);
	for(my $x = $xmin; $x <= $xmax; $x++) {
	    push @p, map { [$x, @$_] } @rest;
	}
    } else {
	for(my $x = $xmin; $x <= $xmax; $x++) {
	    push @p, [$x];
	}
    }
    return @p;
}


package Arg;

sub new {
    my $class = shift;
    my $orig = shift;
    if($::oodebug and not defined $orig) {
	Carp::cluck($orig);
    }
    return bless {
	'orig' => $orig,
    }, ref($class) || $class;
}

sub replace {
    my $self = shift;
    my $replacement_string = shift; # {} {/} {//} {.} {/.}
    if(not defined $self->{$replacement_string}) {
	my $s;
	if($Global::trim eq "n") {
	    $s = $self->{'orig'};
	} else {
	    $s = trim_of($self->{'orig'});
	}
	if($replacement_string eq "{}") {
	    # skip
	} elsif($replacement_string eq "{.}") {
	    $s =~ s:\.[^/\.]*$::; # Remove .ext from argument
	} elsif($replacement_string eq "{/}") {
	    $s =~ s:^.*/([^/]+)/?$:$1:; # Remove dir from argument. If ending in /, remove final /
	} elsif($replacement_string eq "{//}") {
	    # Only load File::Basename if actually needed
	    $Global::use{"File::Basename"} ||= eval "use File::Basename; 1;";
	    $s = dirname($s); # Keep dir from argument.
	} elsif($replacement_string eq "{/.}") {
	    $s =~ s:^.*/([^/]+)/?$:$1:; # Remove dir from argument. If ending in /, remove final /
	    $s =~ s:\.[^/\.]*$::; # Remove .ext from argument
	}
	if($Global::JobQueue->quote_args()) {
	    $s = ::shell_quote_scalar($s);
	}
	$self->{$replacement_string} = $s;
    }
    return $self->{$replacement_string};
}

sub orig {
    my $self = shift;
    return $self->{'orig'};
}

sub trim_of {
    # Removes white space as specifed by --trim:
    # n = nothing
    # l = start
    # r = end
    # lr|rl = both
    # Returns:
    #   string with white space removed as needed
    my @strings = map { defined $_ ? $_ : "" } (@_);
    my $arg;
    if($Global::trim eq "n") {
	# skip
    } elsif($Global::trim eq "l") {
	for $arg (@strings) { $arg =~ s/^\s+//; }
    } elsif($Global::trim eq "r") {
	for $arg (@strings) { $arg =~ s/\s+$//; }
    } elsif($Global::trim eq "rl" or $Global::trim eq "lr") {
	for $arg (@strings) { $arg =~ s/^\s+//; $arg =~ s/\s+$//; }
    } else {
	::error("--trim must be one of: r l rl lr.\n");
	::wait_and_exit(255);
    }
    return wantarray ? @strings : "@strings";
}


package TimeoutQueue;

sub new {
    my $class = shift;
    my $delta_time = shift;

    return bless {
	'queue' => [],
	'delta_time' => $delta_time,
    }, ref($class) || $class;
}

sub process_timeouts {
    # Check if there was a timeout
    my $self = shift;
    # @Global::timeout is sorted by timeout
    while (@{$self->{'queue'}}) {
	my $job = $self->{'queue'}[0];
	if($job->timedout()) {
	    # Need to shift off queue before kill
	    # because kill calls usleep -> process_timeouts
	    shift @{$self->{'queue'}};
	    $job->kill();
	} else {
	    # Because they are sorted by timeout
	    last;
	}
    }
}

sub insert {
    my $self = shift;
    my $in = shift;
    my $lower = 0;
    my $upper = $#{$self->{'queue'}};
    my $looking = int(($lower + $upper)/2);
    my $in_time = $in->timeout();

    # Find the position between $lower and $upper
    while($lower < $upper) {
	if($self->{'queue'}[$looking]->timeout() < $in_time) {
	    # Upper half
	    $lower = $looking+1;
	} else {
	    # Lower half
	    $upper = $looking;
	}
	$looking = int(($lower + $upper)/2);
    }
    # splice at position $looking
    splice @{$self->{'queue'}}, $looking, 0, $in;
}


package Semaphore;

# This package provides a counting semaphore
#
# If a process dies without releasing the semaphore the next process
# that needs that entry will clean up dead semaphores
#
# The semaphores are stored in ~/.parallel/semaphores/id-<name> Each
# file in ~/.parallel/semaphores/id-<name>/ is the process ID of the
# process holding the entry. If the process dies, the entry can be
# taken by another process.

sub new {
    my $class = shift;
    my $id = shift;
    my $count = shift;
    $id=~s/([^-_a-z0-9])/unpack("H*",$1)/ige; # Convert non-word chars to hex
    $id="id-".$id; # To distinguish it from a process id
    my $parallel_dir = $ENV{'HOME'}."/.parallel";
    -d $parallel_dir or mkdir_or_die($parallel_dir);
    my $parallel_locks = $parallel_dir."/semaphores";
    -d $parallel_locks or mkdir_or_die($parallel_locks);
    my $lockdir = "$parallel_locks/$id";
    my $lockfile = $lockdir.".lock";
    if($count < 1) { ::die_bug("semaphore-count: $count"); }
    return bless {
	'lockfile' => $lockfile,
	'lockfh' => Symbol::gensym(),
	'lockdir' => $lockdir,
	'id' => $id,
	'idfile' => $lockdir."/".$id,
	'pid' => $$,
	'pidfile' => $lockdir."/".$$.'@'.::hostname(),
	'count' => $count + 1 # nlinks returns a link for the 'id-' as well
    }, ref($class) || $class;
}

sub acquire {
    my $self = shift;
    my $sleep = 1; # 1 ms
    my $start_time = time;
    while(1) {
	$self->atomic_link_if_count_less_than() and last;
	::debug("Remove dead locks");
	my $lockdir = $self->{'lockdir'};
	for my $d (<$lockdir/*>) {
	    ::debug("Lock $d $lockdir\n");
	    $d =~ m:$lockdir/([0-9]+)\@([-\._a-z0-9]+)$:o or next;
	    my ($pid, $host) = ($1,$2);
	    if($host eq ::hostname()) {
		if(not kill 0, $1) {
		    ::debug("Dead: $d");
		    unlink $d;
		} else {
		    ::debug("Alive: $d");
		}
	    }
	}
	# try again
	$self->atomic_link_if_count_less_than() and last;
	# Retry slower and slower up to 1 second
	$sleep = ($sleep < 1000) ? ($sleep * 1.1) : ($sleep);
	# Random to avoid every sleeping job waking up at the same time
	::usleep(rand()*$sleep);
	if(defined($::opt_timeout) and
	   $start_time + $::opt_timeout > time) {
	    # Acquire the lock anyway
	    if(not -e $self->{'idfile'}) {
		open (A, ">", $self->{'idfile'}) or
		    ::die_bug("write_idfile: $self->{'idfile'}");
		close A;
	    }
	    link $self->{'idfile'}, $self->{'pidfile'};
	    last;
	}
    }
    ::debug("acquired $self->{'pid'}\n");
}

sub release {
    my $self = shift;
    unlink $self->{'pidfile'};
    if($self->nlinks() == 1) {
	# This is the last link, so atomic cleanup
	$self->lock();
	if($self->nlinks() == 1) {
	    unlink $self->{'idfile'};
	    rmdir $self->{'lockdir'};
	}
	$self->unlock();
    }
    ::debug("released $self->{'pid'}\n");
}

sub atomic_link_if_count_less_than {
    # Link $file1 to $file2 if nlinks to $file1 < $count
    my $self = shift;
    my $retval = 0;
    $self->lock();
    ::debug($self->nlinks()."<".$self->{'count'});
    if($self->nlinks() < $self->{'count'}) {
	-d $self->{'lockdir'} or mkdir_or_die($self->{'lockdir'});
	if(not -e $self->{'idfile'}) {
	    open (A, ">", $self->{'idfile'}) or
		::die_bug("write_idfile: $self->{'idfile'}");
	    close A;
	}
	$retval = link $self->{'idfile'}, $self->{'pidfile'};
    }
    $self->unlock();
    ::debug("atomic $retval");
    return $retval;
}

sub nlinks {
    my $self = shift;
    if(-e $self->{'idfile'}) {
	::debug("nlinks".((stat(_))[3])."\n");
	return (stat(_))[3];
    } else {
	return 0;
    }
}

sub lock {
    my $self = shift;
    my $sleep = 100; # 100 ms
    open $self->{'lockfh'}, ">", $self->{'lockfile'}
	or ::die_bug("Can't open semaphore file $self->{'lockfile'}: $!");
    chmod 0666, $self->{'lockfile'}; # assuming you want it a+rw
    $Global::use{"Fcntl"} ||= eval "use Fcntl qw(:DEFAULT :flock); 1;";
    while(not flock $self->{'lockfh'}, LOCK_EX()|LOCK_NB()) {
	if ($! =~ m/Function not implemented/) {
            ::warning("flock: $!");
	    ::warning("Will wait for a random while\n");
	    ::usleep(rand(5000));
	    last;
	}

	::debug("Cannot lock $self->{'lockfile'}");
	# TODO if timeout: last
	$sleep = ($sleep < 1000) ? ($sleep * 1.1) : ($sleep);
	# Random to avoid every sleeping job waking up at the same time
	::usleep(rand()*$sleep);
    }
    ::debug("locked $self->{'lockfile'}");
}

sub unlock {
    my $self = shift;
    unlink $self->{'lockfile'};
    close $self->{'lockfh'};
    ::debug("unlocked\n");
}

sub mkdir_or_die {
    # If dir is not writable: die
    my $dir = shift;
    my @dir_parts = split(m:/:,$dir);
    my ($ddir,$part);
    while(defined ($part = shift @dir_parts)) {
	$part eq "" and next;
	$ddir .= "/".$part;
	-d $ddir and next;
	mkdir $ddir;
    }
    if(not -w $dir) {
	::error("Cannot write to $dir: $!\n");
	::wait_and_exit(255);
    }
}

# Keep perl -w happy
$::opt_x = $Semaphore::timeout = $Semaphore::wait = $::opt_shebang =
0;

