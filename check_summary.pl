#!/usr/bin/perl
# vim:ts=4
# nagios:-epn
###########################################################################
#
# check_summary
# Steve Shipway, 2005-2014.  
# Calculate a value based on a function of other status values.
#
# check_summary [ -f file | -e 'script' ] [-z] [-x] [-s] [-d] [-S statusfile]
#
# version 1.1: added hostgroups
#         1.2: add threshold check
#         1.3: fix typo in threshold check (all statuses coming out as 0)
#         2.0: add Nagios 2 support
#         2.1: add hostname to output on thresh
#         3.0: Add Nagios 3 support
#         3.1: Fix objects.cache usage
#         4.0: livestatus support
#
###########################################################################
# NOTE:
#    You MUST set the file locations below correctly before using this script!
###########################################################################

use strict;
use vars qw/$opt_d $opt_f $opt_e $opt_x $opt_z $opt_s $opt_S $opt_h $opt_L $opt_O/;
use Getopt::Std;
use Text::ParseWords;

###########################################################################
# SET THESE FIRST!
# Depending on which are set, the script will use a different method to
# collect status data.
# First choice: livestatus  
# Second choice: status.dat + objects.cache
# Last choice: status.log + hostgroups.cfg
###########################################################################
#
my($LIVESTATUS)= 'localhost:6557';                 # Livestatus API
my($STATUSDAT) = '/u02/nagios/log/status.dat';     # for nagios 2.x/3.x
my($STATUSLOG) = '/u02/nagios/log/status.log';     # for nagios 1.x
my($HOSTGROUPS)= '/u02/nagios/etc/hostgroups.cfg'; # for nagios 1.x, 2.x
my($OBJCACHE)  = '/u02/nagios/log/objects.cache';  # for nagios 3.x
#
###########################################################################

my($VERSION) = '4.0';
my($SCRIPT)  = '@cluster( /% )'; # default script: all servers summary
my($BR)      = "\n"; # can set to \n if you have Nagios 3 or <br> for nagios 2
my($DEBUG)   = 0;

my($STATUS ) = 3;
my($MESSAGE) = "Null script";

my(%hosts)    = ();
my(%services) = ();
my($usedowntime) = 1; # ignore things in downtime
my($usedisabled) = 1; # ignore things with notify disabled
my($usesoft    ) = 1; # use things in soft states
my(%hostgroups) = ();

my(%map) = ( 
	'OK'=>0, 'WARN'=>1, 'WARNING'=>1, 'CRIT'=>2, 'CRITICAL'=>2,
	'UNKNOWN'=>3, 'UNK'=>3, 'PENDING'=>4,
	'UP'=>0, 'DOWN'=>2, 'UNREACHABLE'=>3,
	0=>0, 1=>1, 2=>2, 3=>3 );

###########################################################################
sub usage {
	print "Version $VERSION\n\n";
	print "check_summary [-x][-s][-d][-h][-z] [-f file | -e 'script'] [-S status.log]\n                    [-O objects.cache][-L livestatusport]\n\n";
	print "-x : Do not ignore hosts/services with notifications disabled\n";
	print "-z : Do not ignore hosts/services in scheduled downtime\n";
	print "-s : Ignore services in a soft alert state\n";
	print "-h : Show this help text\n";
	print "-d : Enable debug mode. Can help track down script errors.\n";
    print "-L : Give Livestatus API (eg: localhost:6557)\n";
	print "-S : Give location of status.log/dat file (default "
		.((-f $STATUSDAT)?$STATUSDAT:$STATUSLOG).")\n";
	print "-O : Give location of objects.cache file (Nagios 3.x) (default $OBJCACHE)\n";
	print "\n";
	print "Script syntax:\n";
	print "Script must resolve to a single value, else it is an error.\n";
	print "Script can contain functions, hosts, services, and literals.\n";
	print "You must quote spaces, or escape with a backstroke.\n\n";
	print "Literals are of the form:\n     status:text\nfor status of OK,WARN,CRIT,UNKNOWN\n\n";
	print "Hosts are of the form:\n     /hostname\nwhere hostname can be a regexp preceeded by a % or a hostgroup preceded by a :\n\n";
	print "Services are of the form:\n     /hostname/servicedesc\nwhere either or both of hostname and servicedesc can be regexps preceeded by %\n";
	print "You can also specify the host as a hostgroup preceded by a :.\n";
	print "If a service is specified using hostgroup and/or regexp, then only matching\nservices are implied.  This may mean no matching services at all!  An error\nis only given if a non-existant explicit hostname/servicename is given.\n\n";
	print "Functions are of the form:\n     \@functionname ( argumentlist )\nwhere argumentlist is a list made up of one or more literals, hosts, services,\nor functions.  The functionname can be any of:\n";
	print "  \@max : Take the maximum value of the statuses in the list\n";
	print "  \@min : Take the minimum value of the statuses in the list\n";
	print "  \@cluster : OK if all are OK, critical if all are critical, else warning\n";
	print "  \@avg : Mean average status, rounded to nearest\n";
	print "  \@median : Median status\n";
	print "  \@map : Change text to the text of item with the same status as the first\n          item in the list.  Status is the status of the first item.  Use this\n          to rewrite the text after calculations.\n";
	print "  \@threshold : First item is  dummy threshold definition item.  Add the   \n          statuses of all other items and compare to warn/crit thresholds in  \n          dummy item.  First item should be of form 0:minc/minw/maxw/maxc and \n          status will go critical if total <minc or >maxc.\n";
	print "  \@mapstatus : Take the first item.  If the status matches that of any of \n          the following items, change the status to the second part of the    \n          matching item\n";
	print "\n";
	print "Example script:\n";
	print ' @map ( @max ( @cluster( /%webserver ) @cluster( /%dbserver ) /router ) "OK:All fine" "WARN:Performance degraded" "CRIT:Service unavailable" )';
	print "\n";
	print ' @mapstatus ( @max( /:hg/DNS ) CRITICAL:WARNING UNKNOWN:WARNING )';
	print "\n";
	print "\n";
	print "check_summary created by Steve Shipway http://www.steveshipway.org/software\n";
	exit(3);
}
###########################################################################
sub error($) { print $_[0]."\n"; exit 3; }
my($donehg) = 0;
my($ml);
sub readlivestatushg {
	return if(!$LIVESTATUS);
	return if($donehg);
	eval { require Monitoring::Livestatus; };
	if($@) {
		print "Livestatus module load failed: $@\n" if($DEBUG);
		return;
	}
    $ml = Monitoring::Livestatus->new(
      peer => $LIVESTATUS, keepalive=>1,
      errors_are_fatal=>0,
    );
    my $hg = $ml->selectall_arrayref("GET hostgroups\nColumns: hostgroup_name members");
    if($Monitoring::Livestatus::ErrorCode) {
        print "Livestatus error: ".($Monitoring::Livestatus::ErrorMessage)."\n"
			if($DEBUG);
        return;
    }

    foreach ( @$hg ) { $hostgroups{$_->[0]} = $_->[1]; }
	$donehg = 1;
}
sub readhostgroupsfile() {
	my($thishg,$line,@list);
	return if($donehg);
	print "Reading hostgroup definitions\n" if($DEBUG);
	open HG,"<$HOSTGROUPS" or return;
	while( $line = <HG> ) {
		chomp $line;
		if( $line =~ /{/ ) { $thishg = ""; @list = (); next; }
		if( $line =~ /hostgroup_name\s+(\S+)/ )  {
			$thishg = $1;
			if(@list) { $hostgroups{$thishg} = [ @list ];
				print "Added hostgroup $thishg\n" if($DEBUG);
				@list = (); $thishg = ""; }
			next;
		}
		if( $line =~ /members\s+(.*)/ ) {
			@list = split /[\s,]+/,$1;
			if($thishg) { $hostgroups{$thishg} = [ @list ];
				print "Added hostgroup $thishg\n" if($DEBUG);
				@list = (); $thishg = ""; }
			next;
		}
	}
	close HG;
	$donehg = 1;
}
sub readobjectscache() {
	my($thishg,$line,@list);
	return if($donehg);
	print "Reading objectscache file\n" if($DEBUG);
	open OC,"<$OBJCACHE" or return;
	while( $line = <OC> ) {
		chomp $line;
		if( $line =~ /{/ ) { $thishg = ""; @list = (); next; }
		if( $line =~ /hostgroup_name\s+(\S+)/ )  {
			$thishg = $1;
			if(@list) { $hostgroups{$thishg} = [ @list ];
				print "Added hostgroup $thishg\n" if($DEBUG);
				@list = (); $thishg = ""; }
			next;
		}
		if( $line =~ /members\s+(.*)/ ) {
			@list = split /[\s,]+/,$1;
			if($thishg) { $hostgroups{$thishg} = [ @list ];
				print "Added hostgroup $thishg\n" if($DEBUG);
				@list = (); $thishg = ""; }
			next;
		}
		if( $line =~ /}/ and $thishg ) {
			$hostgroups{$thishg} = [ @list ] if(@list);
			$thishg = ""; @list = ();
		}
	}
	close OC;
	$donehg = 1;
}
sub readhostgroups() {
	if($LIVESTATUS) {
		readlivestatushg;
	} elsif( -r $OBJCACHE ) {
		readobjectscache();
	} else {
		readhostgroupsfile();
	}
}
sub readlivestatus() {
    my($rv);
	return if(!$LIVESTATUS);
    print "Reading status from livestatus\n" if($DEBUG);

	eval { require Monitoring::Livestatus; };
	if($@) {
		print "Livestatus module load failed: $@\n" if($DEBUG);
		return;
	}
    if(!$ml) {
        $ml = Monitoring::Livestatus->new(
          peer => $LIVESTATUS, keepalive=>1,
        );
    }
    $rv = $ml->selectall_arrayref("GET hosts\nColumns: host_name state notifications_enabled in_notification_period current_attempt max_check_attempts scheduled_downtime_depth plugin_output\n");
    if($Monitoring::Livestatus::ErrorCode) {
        error($Monitoring::Livestatus::ErrorMessage); exit 3;
    }
    foreach ( @$rv ) {
        $hosts{ $_->[0] } = {
                state=>$map{ $_->[1] },
                enabled=>($_->[2] and $_->[3]),
                downtime=>$_->[6],
                output=>$_->[7]
        };
    }
    $rv = $ml->selectall_arrayref("GET services\nColumns: host_name description state notifications_enabled in_notification_period current_attempt max_check_attempts scheduled_downtime_depth plugin_output");
    if($Monitoring::Livestatus::ErrorCode) {
        error($Monitoring::Livestatus::ErrorMessage); exit 3;
    }
    foreach ( @$rv ) {
        $services{ $_->[0] }{ $_->[1] } = {
                state=>$map{ $_->[2] },
                enabled=>($_->[3] and $_->[4]),
                downtime=>$_->[7],
                output=>$_->[8],
                soft=>(($_->[5]<$_->[6])?1:0),
                try=>$_->[5],
                count=>$_->[6],
        };
    }

}

sub readstatuslog() {
	open LOG, "<$STATUSLOG" or error("Unable to open status log");
	while ( <LOG> ) {
		if( /^............ HOST;([^;]+);([^;]+);\d+;\d+;\d+;\d+;\d+;\d+;\d+;\d+;(\d);\d+;\d+;\d+;\d+;.+;(\d+);\d+;\d+;(.*)$/ ) {
			$hosts{$1} = { state=>$map{$2}, enabled=>$3, downtime=>$4, output=>$5 };
			print "Added host $1: ".$map{$2}." $5\n" if($DEBUG);
			next;
		}
		if( /^............ SERVICE;([^;]+);([^;]+);([^;]+);(\d+)\/(\d+);[^;]+;\d+;\d+;[^;]+;\d+;\d+;\d+;\d+;\d+;[^;]+;\d+;\d+;\d+;\d+;\d+;\d+;(\d);\d+;\d+;\d+;\d+;[^;]+;(\d+);\d+;\d+;\d+;(.*)$/ ) {
			$services{$1}{$2} = { state=>$map{$3}, enabled=>$6, downtime=>$7, output=>$8, try=>$4 , count=>$5, soft=>0  };
			$services{$1}{$2}{soft} = 1 if($3 and ($3 ne 'OK') and ($4<$5) );
			next;
		}
	}
	close LOG;
	# Should we also parse the hostgroups file here?
}
sub readstatusdat() {
	my($h,$svc) = ('','');

	open LOG, "<$STATUSDAT" or error("Unable to open status file");
	while ( <LOG> ) {
		if( /^\s*}/ ) { 
			if($svc) {
				$services{$h}{$svc}{soft} = 0;
				$services{$h}{$svc}{soft} = 1 
					if($services{$h}{$svc}{state} and
					($services{$h}{$svc}{count}> $services{$h}{$svc}{try}));
			}
			$h = $svc = ''; next; }
		if( /^\s*host_name\s*=\s*(\S+)/ ) { $h = $1; next; }
		if( /^\s*service_description\s*=\s*(.*\S)/ ) { $svc = $1; next; }
		# hosts
		next if(!$h);
		if($svc) {
		if( /^\s*plugin_output\s*=\s*(.*\S)/ ) { $services{$h}{$svc}{output} = $1; next; }
		if( /^\s*scheduled_downtime_depth\s*=\s*(\d+)/ ) { $services{$h}{$svc}{downtime} = $1; next; }
		if( /^\s*current_state\s*=\s*(\d+)/ ) { $services{$h}{$svc}{state} = $1; next; }
		if( /^\s*notifications_enabled\s*=\s*(\d)/ ) { $services{$h}{$svc}{enabled} = $1; next; }
		if( /^\s*current_attempt\s*=\s*(\d+)/ ) { $services{$h}{$svc}{try} = $1; next; }
		if( /^\s*max_attempts\s*=\s*(\d+)/ ) { $services{$h}{$svc}{count} = $1; next; }
		} else {
		if( /^\s*plugin_output\s*=\s*(.*\S)/ ) { $hosts{$h}{output} = $1; next; }
		if( /^\s*scheduled_downtime_depth\s*=\s*(\d+)/ ) { $hosts{$h}{downtime} = $1; next; }
		if( /^\s*current_state\s*=\s*(\d+)/ ) { $hosts{$h}{state} = $1; next; }
		if( /^\s*notifications_enabled\s*=\s*(\d)/ ) { $hosts{$h}{enabled} = $1; next; }
		}
	}
	close LOG;
}
sub readstatus() {
	if($LIVESTATUS) {
		readlivestatus; # preferred method
	} elsif( -r $STATUSDAT ) {
		readstatusdat; # Nagios 2 or 3 detected
	} else {
		readstatuslog; # must be nagios 1
	}
}

##############################################################################
sub printlist {
	my($rv);
	$rv = "";
	foreach ( @_ ) { if( ref $_ ) { $rv.=$_->[0]; } else { $rv.=$_; };
		$rv .=", "; }
	return $rv;
}
##############################################################################
my(@script) = ();
sub hwildcard {
	my($p) = $_[0];
	my(@rv) = ();

	return ($p) if( $p !~ /^[:\%]/ ); # not a pattern
	
	# hostgroups *TO BE DONE*
	if( $p =~ /^:/ ) {
		$p =~ s/^://;
		readhostgroups();
		print "Hostgroup [$p]\n" if($DEBUG);
		if( defined $hostgroups{$p} ) {
			@rv = @{$hostgroups{$p}};
		} elsif($DEBUG) { print "NOT FOUND\n"; }
		return (@rv);
	}

	# wildcards
	$p =~ s/^\%//;  $p = "." if(!$p);
	print "Host wildcard [$p]\n" if($DEBUG);
	foreach ( keys %hosts ) { push @rv,$_ if( /$p/ ); }
#	print "Return: ".(join ",",@rv)."\n" if($DEBUG);
	return (@rv);
}
sub swildcard {
	my($h,$p) = @_;
	my(@rv) = ();

	if( $p !~ /^\%/ ) { # not a pattern
		push @rv, $p; # if(defined $services{$h}{$p});
		return (@rv);
	}
	$p =~ s/^\%//; $p = "." if(!$p);
	print "Service wildcard [$p] for host [$h]\n" if($DEBUG);
	foreach ( keys %{$services{$h}} ) { 
		print "Checking $_\n" if($DEBUG);
		if( $_=~/$p/ ){ push @rv,$_ ; print "OK\n" if($DEBUG); }
	}
	return (@rv);
}
sub expand {
	my($h,$s);
	my($hp,$sp);
	my(@newscript) = ();
	foreach ( @script ) {
		next if(!$_ or /^[\s,]*$/ ); # ignore blank tokens
		if( /^[\s,]*['"]/ ) { s/^[\s,]*['"]//; s/['"][\s,]*$//; } 
		else { s/^[\s,]+//; s/[\s,]+$//; }
		if( /^\)/ ) {
			while( s/\)// ) { push @newscript, ")"; }
			next;
		}
		if( /^[@\(]/ ) { push @newscript, $_; next; } # function
		if( /^\/(.*)\/(.*)/ ) {
			# host and service
			($hp,$sp) = ($1,$2);
			print "Expanding service /$hp/$sp\n" if($DEBUG);
			foreach $h ( hwildcard( $hp ) ) {
				if( ! defined $hosts{$h} ) { error "Unrecognised host $h"; }
				foreach $s ( swildcard( $h, $sp ) ) {
					if( ! defined $services{$h}{$s} ) { 
						next if($hp=~/^[:%]/);
						error "Unrecognised service $h/$s"; 
					}
					push @newscript, [ $services{$h}{$s}{state}, $services{$h}{$s}{output},$h,$s ]
						unless( ($usedowntime and $services{$h}{$s}{downtime})
							or ($usedisabled and !$services{$h}{$s}{enabled}) 
							or (!$usesoft and $services{$h}{$s}{soft})
						);
				}
			}
			next;
		}
		if( /^\/(.*)/ ) {
			# host 
			$hp = $1;
			print "Expanding host /$hp\n" if($DEBUG);
			foreach $h ( hwildcard( $hp ) ) {
				if( ! defined $hosts{$h} ) { error "Unrecognised host $h"; }
				push @newscript, [ $hosts{$h}{state}, $hosts{$h}{output},$h,'' ]
					unless( ($usedowntime and $hosts{$h}{downtime})
						or ($usedisabled and !$hosts{$h}{enabled}) );
			}
			next;
		}
		# if we are here, then its a literal
		if( /(.*):(.*)/ ) {
			if(! defined $map{$1} ) { error "Bad state $1"; }
			push @newscript, [ $map{$1}, $2,'' ,'' ];
			next;
		}
		error "Cannot parse script ($_)";
		last;
	}

	@script = @newscript;
}
sub dofunction($) { # process the function at index
	my($idx) = $_[0];
	my(@params) = ();
	my($lstart, $lend);
	my(@rv) = ();
	my($fn, $rv, $output);
	my($t,$n,$min,$max,$err);
	my($fh,$fs) = ('','');

	# first, find the end of the parameter list.
	if($script[$idx] !~ /^@/) { 
		error "Not a function at position $idx: ".$script[$idx]; }
	if($script[$idx+1] !~ /^\(/) { 
		error "Expected bracket at position $idx but found ".$script[$idx]; }
	$lstart = $idx+2;
	$lend = $lstart;
	while( $lend <= $#script and $script[$lend]!~/^\)/) { $lend++; }
	if( $lend > $#script ) { 
		error "Expected closing bracket missing (function ".$script[$idx]." at position $idx)."; }
	$lend--;

	@params = @script[$lstart..$lend] if( $lstart <= $lend );
	$fn = $script[$idx];
	if($DEBUG) {
		print "Script: ".(printlist @script)."\n";
		print "IDX: $idx  param=$lstart .. $lend\n";
		print "Function: $fn\n";
		print "Params: ".(printlist @params)."\n";
	}
	# check parameters
	foreach (@params) {
		if( ! ref $_ ) { error "Unexpected constant '$_' in parameters"; }
	}

	($rv, $output) = ( $map{UNKNOWN}, "Cannot determine result" );
	if( $fn =~ /\@max/i ) {
		($rv,$output) = (-1,"");
		foreach ( @params ) { # Identify the maximum status.
			if(($_->[0]>$rv) and ($_->[0]<3)) { 	
				$rv = $_->[0]; 
			}
		}
		if($rv<0) { ($rv,$output)=(3,"Unknown status"); }
		foreach ( @params ) { # Identify the maximum status.
			if($_->[0]==$rv) { 	
				$fh = $_->[2];
				$fs = $_->[3];
				$output.=$BR if($output);
				if($fh){$output.=$fh;$output.="/$fs" if($fs);$output.=":";}
				$output .= $_->[1]; 
			}
		}
		$output = "All parameters OK" if(!$output);
	} elsif( $fn =~ /\@min/i ) {
		($rv,$output) = (3,"");
		foreach ( @params ) {
			if( $_->[0] <= $rv ) { 
				$rv = $_->[0]; 
				$fh = $_->[2];
				$fs = $_->[3];
				$output .= $BR if($output);
				if($fh){$output.=$fh;$output.="/$fs" if($fs);$output.=":";}
				$output .= $_->[1]; 
			}
		}
		$output = "All parameters OK" if(!$rv);
		$output = "All values unknown" if(!$output);
	} elsif( $fn =~ /\@av(era)?g/i ) {
		($t,$n)=(0,0);
		foreach( @params ) { $t += $_->[0]; $n++; }
		if( $n < 1 ) {
			($rv,$output) = (3,"No items in list");
		} else {
			$t = int( $t/$n + 0.500001 );
			($rv, $output) = ( $t, "Average status" );
		}
	} elsif( $fn =~ /\@median/i ) {
		($rv,$output)=(3,"Function not yet written");
	} elsif( $fn =~ /\@clus/i ) {
		($rv,$output) = (0,"All items OK");
		$min = 3; $max = 0;
		$err = "";
		foreach ( @params ) {
			if( $_->[0] < $min ) { $min = $_->[0]; }
			if( $_->[0] > $max ) { $max = $_->[0]; }
			if( $_->[0] > 0 ) {
				$err .= $BR if($err);
				if($_->[2]){$err.=$_->[2];$err.="/".$_->[3] if($_->[3]);$err.=":";}
				$err .= $_->[1];
			}
		}
		if( $min == 3 ) {
			($rv,$output) = (3, "All status unknown");
		} elsif( $min == 2 ) {
			($rv,$output) = (2, "System Critical:$BR$err");
		} elsif( $max > 0 ) {
			($rv,$output) = (1, "System performance degraded:$BR$err");
		}
	} elsif( $fn =~ /\@mapstatus/i ) {
		if(!@params) {
			($rv,$output) = (3, "No parameters given");
		} else {
			($rv, $output) = @{$params[0]}; 
			shift @params;
			foreach ( @params ) {
				if( $_->[0] == $rv ) {
					if(defined $map{$_->[1]}) {
						$rv = $map{$_->[1]};
					} else { $rv = $map{'UNKNOWN'}; }
				}
			}
			$output = $err if($err);
		}
	} elsif( $fn =~ /\@map/i ) {
		# change message of first to match message of subsequent item(s) with 
		# the same status.
		$err = "";
		if(!@params) {
			($rv,$output) = (3, "No parameters given");
		} else {
			($rv, $output) = @{$params[0]}; 
			shift @params;
			foreach ( @params ) {
				if( $_->[0] == $rv ) {
					$err .= $BR if($err);
					$err .= $_->[1];
				}
			}
			$output = $err if($err);
		}
	} elsif( $fn =~ /\@thresh/i ) {
		my($tot) = 0;
		my($t,$a,$b,$c,$d);
		$err = "";
		$t = $params[0][1];
		if( $t =~ /(\d+)\/(\d+)\/(\d+)\/(\d+)/ ) {
			($a,$b,$c,$d)=($1,$2,$3,$4);
			shift @params; # lose the threshold definition
			foreach ( @params ) { $tot += $_->[0]; }
			if( $tot < $a or $tot > $d ) {
				($rv,$output) = (2,"Status is CRITICAL ($tot)");
			} elsif( $tot < $b or $tot > $c ) {
				($rv,$output) = (1,"Status is WARNING ($tot)");
			} else {
				($rv,$output) = (0,"Status is OK ($tot)");
			}
		} else {
			($rv,$output) = (3, "Wrong format for thresholds:$t");
		}
	} else { error "Unknown function $fn"; }

	# Create the new script array
	@rv = @script[0..($idx-1)] if($idx>0);
	push @rv, [$rv,$output,$fh,$fs];
	push @rv, @script[($lend+2)..$#script] if(($lend+1)<$#script);
	@script = @rv;
    if($DEBUG) {
        print "AFTER Script: ".(printlist @script)."\n";
    }
}

sub parsescript() {
	my($done) = 0;
	my($idx);

	@script = quotewords( '[\s,()]+', 'delimiters', $SCRIPT );
	expand;
	do {
		$done = 1;
		$idx = $#script; # evaluate functions right to left
		while( $idx >= 0 ) {
			if( !ref $script[$idx] and $script[$idx]=~/^@/ ) {
				$done = 0; # keep going
				last;
			}
			$idx--;
		}
		dofunction($idx) if(!$done);
	} while(!$done);
	if( $#script == 0 ) {
		($STATUS,$MESSAGE) = @{$script[0]};
	} else {
		($STATUS,$MESSAGE) = 
			( $map{UNKNOWN}, "Script did not reduce to one value" );
	}
}
##############################################################################

getopts( "L:df:e:xzshS:O:" );
usage if($opt_h);
$usedowntime = 0 if($opt_z);
$usedisabled = 0 if($opt_x);
$usesoft     = 0 if($opt_s);
$STATUSLOG = $opt_S if($opt_S);
$OBJCACHE  = $opt_O if($opt_O);
$LIVESTATUS= $opt_L if($opt_L);
$SCRIPT    = $opt_e if($opt_e);
$DEBUG = 1 if($opt_d);
if($opt_f) {
	error("Cannot read script file") if(! -r $opt_f);
	open SF, "<$opt_f" or error("$opt_f: $!");
	$SCRIPT = "";
	while (<SF>) { $SCRIPT .= " $_" unless(/^\s*#/); }
	close SF;
}

readstatus;
parsescript;

print "$MESSAGE\n";
print "status $STATUS\n" if($DEBUG);
exit $STATUS;
