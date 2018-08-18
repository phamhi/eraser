#!/usr/bin/ksh
#
# TSO Eraser(tm) 2014
#

#==============================================================================
###
## display the date in a specific format, e.g. Oct 16, 2012 11:18:45 AM EDT
#
show_date () { $DATE "+%b %d, %Y %T %p %Z"; }

###
## IFS magic
#
save_ifs () { OLD_IFS=$IFS; }
o_ifs () { IFS=$OLD_IFS; }
n_ifs () { IFS=$("$PRINTF" "\n\b"); }

###
## 
#
first_time () {
	#set -vx

	local temp_queue
	local exemption_check=false
	local item_value

	#####
	## self prerequisite check
	##

	# expect the global directives in the configuration file
	for item in $GLOBAL_DIRECTIVE_LIST; do
		
		# skip pre-req check for items in GLOBAL_EXEMPTION_LIST
		for exempt in $GLOBAL_EXEMPTION_LIST; do
			if [[ "$item" = "$exempt" ]]; then
				exemption_check=true
				continue
			fi
		done
		if [[ "$exemption_check" = "true" ]]; then
			exemption_check=false
			continue
		fi

		eval item_value='$'$item
		if [[ "${item_value:-x}" = "x" ]]; then
			"$PRINTF" "<$(show_date)> <Error> <$($HOSTNAME)> <$($BASENAME $0)> \
Fatal error occurred: directive \"$item\" has not been set in \"$CONFIG_FILE\".\n" >&2
			exit 1
		fi
	done

	# parallel.pl utility check
	if [[ ! -e "$GLOBAL_PARALLEL_BIN" ]] || [[ ! -x "$GLOBAL_PARALLEL_BIN" ]]; then
		"$PRINTF" "<$(show_date)> <Error> <$($HOSTNAME)> <$($BASENAME $0)> \
Fatal error occurred: either \"$GLOBAL_PARALLEL_BIN\" does not exist or is not executable.\n" >&2
		exit 1
	fi

	# invalidates the user's timestamp for security reason
	if ! "$GLOBAL_SUDO_BIN" -K 2>/dev/null; then
		"$PRINTF" "<$(show_date)> <Error> <$($HOSTNAME)> <$($BASENAME $0)> \
Fatal error occurred: something went wrong when trying to execute \"$GLOBAL_SUDO_BIN\".\n" >&2
		exit 1
	fi

	[ -e "$CUR_DIR"/"VERSION" ] && VERSION=$($HEAD -1 "$CUR_DIR"/"VERSION")
	# default to version 1.0
	: ${VERSION:=1.0}

	echo "<$(show_date)> <Notice> <$($HOSTNAME)> Starting TSO Log Management utility version $VERSION."

	n_ifs
	for directive in $GLOBAL_DIRECTIVE_LIST; do
		directive=$(echo $directive|"$SED" "s/^[ 	]\{1,\}//"|"$SED" "s/[ 	]\{1,\}$//")
		
		case "$directive" in
			GLOBAL_FILE_PATTERN|GLOBAL_DIR_QUEUE)
				eval temp_queue='$'$directive

				if [[ -z "$temp_queue" ]]; then
						echo "<$(show_date)> <Notice> <$($HOSTNAME)> The directive $directive has not been set or is empty."
						continue
				fi
				echo "<$(show_date)> <Notice> <$($HOSTNAME)> The directive $directive is set as follow:"
				echo "------------------------------------------------------------------------------------------------------------------------"

				for i_re in $temp_queue; do
					i_re=$(echo $i_re|"$SED" "s/^[ 	]\{1,\}//"|"$SED" "s/[ 	]\{1,\}$//")
					"$PRINTF" "\t$i_re\n"
				done

				echo "------------------------------------------------------------------------------------------------------------------------"
				;;
			*)
				echo "<$(show_date)> <Notice> <$($HOSTNAME)> The directive $directive is set to \"$(eval print \$$directive)\"."
				;;
		esac
	done
	o_ifs

	if [[ "$GLOBAL_FLUSH" = "true" ]]; then
		echo "<$(show_date)> <Notice> <$($HOSTNAME)> Forcing system to flush unwritten buffers (this may take a couple of seconds)."
		$SYNC
	fi

	TOTAL_USERS_PROCESSED=0
	TOTAL_FILES_DELETED=0
	TOTAL_FILES_COMPRESSED=0
	FIRST_TIME_FLAG=true

	TOTAL_ALL_KB_FREED=0
	TOTAL_DELETE_KB_FREED=0
	TOTAL_COMPRESS_KB_FREED=0
	TOTAL_COMPRESS_PRE_KB_COUNT=0

	ALL_COMPRESSED_FILES=
}

###
## 
#
last_time () {
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> No more items in the queue."

	if [[ "$GLOBAL_FLUSH" = "true" ]]; then
		echo "<$(show_date)> <Notice> <$($HOSTNAME)> Forcing system to flush unwritten buffers (this may take a couple of seconds)."
		$SYNC
	fi

	local total_post_kb_count

	if [[ -n "$ALL_COMPRESSED_FILES" ]]; then
		n_ifs
		total_post_kb_count=$("$DU" -k `"$PRINTF" $ALL_COMPRESSED_FILES`|"$AWK" 'BEGIN{total=0}{$total+=$1}END{print $total}')
		o_ifs

		TOTAL_COMPRESS_KB_FREED=$((TOTAL_COMPRESS_PRE_KB_COUNT - total_post_kb_count))
	fi

	TOTAL_ALL_KB_FREED=$((TOTAL_DELETE_KB_FREED + TOTAL_COMPRESS_KB_FREED))


	if ((GLOBAL_VERBOSE_LOGGING > 0)); then
		echo "------------------------------------------------------------------------------------------------------------------------"
		echo "[***total_post_kb_count***]"
		echo "---------------------------"
		echo $total_post_kb_count
		echo "---------------------------"
		echo "[***TOTAL_COMPRESS_PRE_KB_COUNT***]"
		echo "-----------------------------------"
		echo $TOTAL_COMPRESS_PRE_KB_COUNT
		echo "------------------------------------------------------------------------------------------------------------------------"
	fi

	echo "<$(show_date)> <Notice> <$($HOSTNAME)> A total of $((JOB_COUNTER)) jobs ran."
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> A total of $TOTAL_FILES_DELETED files have been deleted."
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> A total of $TOTAL_FILES_COMPRESSED files have been compressed."
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> A total of ${TOTAL_DELETE_KB_FREED}kB have been freed from deletion."
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> A total of  ${TOTAL_COMPRESS_KB_FREED}kB have been freed from compression."
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> A total of ${TOTAL_ALL_KB_FREED}kB have been freed from ALL methods."
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> This script ran for approximately $SECONDS second(s)."
	echo "<$(show_date)> <Notice> <$($HOSTNAME)> Finished."
}

###
## locate using "find", sort using "ls -tr", filter using "fuser"
#
find_fuser() {
	#set -vx
	
	# expecting mtime
	# expecting action
    for i in "$@"; do eval local "$i"; done

	local rc
	local list
	local temp_list

	local find_param="-type f -a
				-user $JOB_USER -a
				-mtime +$mtime
				"
	# false
	[[ "$JOB_RECURSIVE" != "true" ]] && find_param="-prune $find_param" 
	[[ "$action" = compress ]] && find_param="$find_param -a ! -name *.gz"

	#####
	## locate files
	##
	rc=
	if [[ "$USE_SUDO" = "true" ]]; then
		temp_list=$(cd / && "$SUDO_BIN" -u "$JOB_USER" "$FIND" "$JOB_DIR"/* $find_param 2>/dev/null)
	else
		temp_list=$(cd / && "$FIND" "$JOB_DIR"/* $find_param 2>/dev/null)
	fi
	rc=$?

	if [[ -n "$temp_list" ]]; then 
		list=$temp_list
	else
		# rc 1 for unable to locate files (either empty dir or wrong parameter)
		return $rc
	fi

	#####
	## sort by time-reverse
	##	
	## disabled for now

	#####
	## filter using fuser to detect file locking
	##
	n_ifs
	
	if [[ $(uname) = "AIX" ]]; then
		if [[ "$USE_SUDO" = "true" ]]; then
			temp_list=$("$SUDO_BIN" -u "$JOB_USER" "$FUSER" $list 2>&1|"$EGREP" -v '[0-9]$' 2>/dev/null|"$SED" 's/: $//' 2>/dev/null)
		else
			temp_list=$("$FUSER" $list 2>&1|"$EGREP" -v '[0-9]$' 2>/dev/null|"$SED" 's/: $//' 2>/dev/null)	
		fi
	else
		if [[ "$USE_SUDO" = "true" ]]; then
			temp_list=$("$SUDO_BIN" -u "$JOB_USER" "$FUSER" $list 2>&1|"$EGREP" -v '[0-9]+o$' 2>/dev/null|"$SED" 's/: $//' 2>/dev/null)
		else
			temp_list=$("$FUSER" $list 2>&1|"$EGREP" -v '[0-9]+o$' 2>/dev/null|"$SED" 's/: $//' 2>/dev/null)	
		fi
	fi
	
	o_ifs
	if [[ -n "$temp_list" ]]; then 
		list=$temp_list
	else
		# fuser didn't work or returns an empty list
		return 90
	fi


	# assume everything went well at this point
	"$PRINTF" "$list"
	return 0
}


###
## Perform certain action: delete or compress
#
take_action () {
	#set -x
	
	# expecting mtime
	# expecting action
    for i in "$@"; do eval local "$i"; done

	local list
	local num_of_files
	local filtered_list
	local temp
	local rrc
	local reason

	echo "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> <$action> Searching directory \"$JOB_DIR\"..."

	list=$(find_fuser mtime=$mtime action=$action)

	rrc=$?
	case "$rrc" in
		0) ;;
		1) reason="unable to perform locate" ;;
		127) reason="unable to perform time-reverse sort" ;;
		90) reason="unable to perform fuser or got no empty result";;
		*) reason="unknown"
	esac

	if [[ -z "$list" ]]; then
		echo "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> <$action> No match (RC=$rrc). Skipping to the next directory in the list."
		return 1
	fi
	
	#####
	## perform filter matching
	##

	echo "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> <$action> Applying the matching patterns against the files in the directory..."

	n_ifs
	for i_re in $JOB_FILE_PATTERN; do
		#i_re=$("$PRINTF" $i_re|$PERL -ple "s/^\s+//")
		i_re=$(echo $i_re|"$SED" "s/^[ 	]\{1,\}//"|"$SED" "s/[ 	]\{1,\}$//")

		temp=$("$PRINTF" "$list"|"$PERL" -wnl -e "m{$i_re} and print;")

		if [[ -n "$filtered_list" ]]; then
			filtered_list=$(print "${filtered_list}\n${temp}")
		else
			filtered_list=$temp
		fi
	done
	o_ifs
	
	if [[ -z "$filtered_list" ]]; then
		echo "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> <$action> No files met the \"older than\" \
$mtime days criterion to "$action" for \"$JOB_USER\". Skipping."
		return 1
	fi

	n_ifs
	list=$(cd / && "$LS" -tr $filtered_list|"$SORT"|"$UNIQ")	
	o_ifs

	#####
	## perform primary execution: delete or compress
	##
	num_of_files=$(echo "$list"|"$WC" -l|"$AWK" '{print $1}')

	"$PRINTF" "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> <$action> Found $num_of_files file(s) \
that are older than $mtime days. Proceed to ${action} the files...\n"
	echo "------------------------------------------------------------------------------------------------------------------------"
	n_ifs
	for i in $list; do
		"$PRINTF" "    "
		"$LS" -l "$i"
	done
	o_ifs
	echo "------------------------------------------------------------------------------------------------------------------------"


#############
	# tabulate the total kBs of files prior to any action
	n_ifs
	pre_kb_count=$("$DU" -k $list|"$AWK" 'BEGIN{total=0}{$total+=$1}END{print $total}')
	o_ifs


	if ((GLOBAL_VERBOSE_LOGGING > 0)); then
		echo "------------------------------------------------------------------------------------------------------------------------"
		echo "[***pre_kb_count***]"
		echo "--------------------"
		echo $pre_kb_count
		echo "------------------------------------------------------------------------------------------------------------------------"
	fi

#############

	if [[ "$JOB_DRY_RUN" = "true" ]]; then
		n_ifs
		if [[ "$JOB_USE_SUDO" = "true" ]]; then
			"$JOB_SUDO_BIN" -u "$JOB_USER" "$LS" -l $list
		else
			"$LS" -l $list
		fi
		o_ifs
		echo "------------------------------------------------------------------------------------------------------------------------"
		return 0
	fi

	case "$action" in 
		delete) ((TOTAL_FILES_DELETED+=num_of_files)) ;;
		compress) ((TOTAL_FILES_COMPRESSED+=num_of_files)) ;;
	esac

	case "$action" in 
		###
		# DELETE
		###
		delete)
			n_ifs
			if [[ "$JOB_USE_SUDO" = "true" ]]; then
				for i in $list;do
					exec 6>&2 2>&1
					set -x
					"$JOB_SUDO_BIN" -u "$JOB_USER" "$RM" -f $i
					set +x
					exec 2>&6 6>&-
				done
			else
				for i in $list;do
					exec 6>&2 2>&1
					set -x
					"$RM" -f $i
					set +x
					exec 2>&6 6>&-
				done
			fi
			o_ifs
			echo "------------------------------------------------------------------------------------------------------------------------"
			# tabulate freed disk space
			if ((pre_kb_count > 0)); then
				((TOTAL_DELETE_KB_FREED += pre_kb_count))
				"$PRINTF" "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> <$action> A total of ${pre_kb_count}kB has been freed.\n"
			fi

			;;
		###
		# COMPRESS
		###
		compress)			
			exec 6>&2 2>&1
			if [[ "$JOB_USE_SUDO" = "true" ]]; then
				"$JOB_PARALLEL_BIN" -j"$JOB_CHILD_PROCESS" --verbose --nice "$JOB_NICENESS" "$JOB_SUDO_BIN" -u "$JOB_USER" "$GZIP" -f ::: "$list"			
			else
				"$JOB_PARALLEL_BIN" -j"$JOB_CHILD_PROCESS" --verbose --nice "$JOB_NICENESS" "$GZIP" -f ::: "$list"			
			fi
			exec 2>&6 6>&-
			echo "------------------------------------------------------------------------------------------------------------------------"
			# tabulate total pre kB count disk space for last run
			if ((pre_kb_count > 0)); then
				((TOTAL_COMPRESS_PRE_KB_COUNT+=pre_kb_count))
			fi

			
			## keep a record of all of the compressed files for later du
			n_ifs
			for i in $list; do
				if [[ -n "$ALL_COMPRESSED_FILES" ]]; then
					ALL_COMPRESSED_FILES="${ALL_COMPRESSED_FILES}\n${i}.gz"
				else 
					ALL_COMPRESSED_FILES="${i}.gz"
				fi
			done
			o_ifs

			if ((GLOBAL_VERBOSE_LOGGING > 0)); then
				echo "------------------------------------------------------------------------------------------------------------------------"
				echo "[***ALL_COMPRESSED_FILES***]"
				echo "----------------------------"
				printf "$ALL_COMPRESSED_FILES"
				echo
				echo "------------------------------------------------------------------------------------------------------------------------"
			fi

			;;
	esac

	return 0
}

###
## 
#
override_global () {
	# set -vx
	
	local bare_keyword=
	local job_appended=
	local value=
	local user_overwritten_flag=false

	if [[ "${JOB_USER:-x}" = x ]]; then
		# true if not defined
		eval JOB_USER='$'GLOBAL_USER
		user_overwritten_flag=true
	fi
	
	for directive in $GLOBAL_DIRECTIVE_LIST; do
		bare_keyword=${directive#GLOBAL_}
		job_appended="JOB_${bare_keyword}"

		# true not defined
		if eval [[ "\${$job_appended:+x}" = x ]]; then
			# local JOB definition found
			eval value='$'$job_appended

			case "$directive" in
				GLOBAL_FILE_PATTERN|GLOBAL_DIR_QUEUE)
					"$PRINTF" "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> Override found: the new value for $job_appended is now:\n"
					"$PRINTF" "------------------------------------------------------------------------------------------------------------------------\n"

					n_ifs
					for i_re in $value; do
						i_re=$(echo $i_re|"$SED" "s/^[ 	]\{1,\}//"|"$SED" "s/[ 	]\{1,\}$//")
						"$PRINTF" "\t$i_re\n"
					done
					o_ifs

					"$PRINTF" "------------------------------------------------------------------------------------------------------------------------\n"								;;
				*) 
					if [[ "$user_overwritten_flag" != "true" ]]; then
						"$PRINTF" "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> Override found: the new value for $job_appended is now \"$value\".\n"
					fi
					;;
			esac		

		fi

		# if not defined, use the global values
		eval $job_appended='$'{$job_appended:-\$$directive}
	done
	#set +vx
}

###
## 
#
execute_job() {

	local directive_list

	if [[ "$FIRST_TIME_FLAG" != "true" ]]; then
		"$PRINTF" "<$(show_date)> <Error> <$($HOSTNAME)> Internal error: it looks like --first-time has not been executed yet.\n"
		"$PRINTF" "<$(show_date)> <Error> <$($HOSTNAME)> Hint: check the \"$CONFIG_FILE\" file.\n"
		exit 1
	fi

	# no point continuing if JOB isn't enabled
	if [[ "${JOB_ENABLED:-x}" = x ]]; then
		# true if not defined
		[[ "$GLOBAL_ENABLED" != "true" ]] && return 1
	else
		[[ "$JOB_ENABLED" != "true" ]] && return 1
	fi

	##
	## assuming everything is good at this point
	##
	((JOB_COUNTER+=1))


	# proceed to override the GLOBAL variables with the JOB ones
	override_global

	# minimum requirements
	directive_list="
		JOB_USER
		JOB_DIR_QUEUE
		JOB_FILE_PATTERN		
	"

	for item in ${directive_list[@]}; do
		eval item_value='$'$item
		if [[ -z "$item_value" ]]; then
			"$PRINTF" "<$(show_date)> <Error> <$($HOSTNAME)> <job:$JOB_COUNTER> Fatal error occurred: directive \"$item\" has not been defined.\n" >&2
			"$PRINTF" "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> Skipping to the next job...\n" >&2
			return 2
		fi
	done

	"$PRINTF" "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> Processing job number $JOB_COUNTER for \"$JOB_USER\" user.\n"

	if [[ $(uname) = "AIX" ]]; then
		echo "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> Detected AIX. Skipping automatic authentication test."
	else
		if [[ "$JOB_USE_SUDO" = "true" ]]; then
			if ! "$GLOBAL_SUDO_BIN" -n -u "$JOB_USER" /bin/id >/dev/null 2>&1; then
				echo "<$(show_date)> <Error> <$($HOSTNAME)> <job:$JOB_COUNTER> Fatal error occurred: failed to perform automatic authentication (using sudo) to \"$JOB_USER\"."
				echo "<$(show_date)> <Notice> <$($HOSTNAME)> <job:$JOB_COUNTER> Skipping to the next job."
				return 3
			fi
		fi
	fi

	# using n_ifs because directories could potentially have spaces
	n_ifs
	for JOB_DIR in $JOB_DIR_QUEUE; do
		#JOB_DIR=$("$PRINTF" $JOB_DIR|"$PERL" -ple "s/^\s+//")
		JOB_DIR=$(echo $JOB_DIR|"$SED" "s/^[ 	]\{1,\}//"|"$SED" "s/[ 	]\{1,\}$//")
		o_ifs

		if [[ ! -d "$JOB_DIR" ]]; then 
			echo "<$(show_date)> <Warning> <$($HOSTNAME)> <job:$JOB_COUNTER> <$JOB_USER> The following directory does not exist: \"$JOB_DIR\". Skipping..."
			continue
		fi

		take_action mtime=$JOB_RET_DELETE action=delete
		take_action mtime=$JOB_RET_COMPRESS action=compress
	done
	o_ifs

	return 0
}

###
##
#
unset_job_def () {
	#set -vx

	local bare_keyword=
	local job_appended=
	local value=

	for directive in $GLOBAL_DIRECTIVE_LIST; do
		bare_keyword=${directive#GLOBAL_}
		job_appended="JOB_${bare_keyword}"

		# true not defined
		if eval [[ "\${$job_appended:+x}" = x ]]; then
			# local JOB definition found
			#set -x
			eval unset $job_appended
			#set +x			
		fi
	done
}

#==============================================================================
#

CONFIG_FILE=config.properties

# overrides in case of minor UNIX incompatibility
AWK=awk
BASENAME=basename
DATE=date
DIRNAME=dirname
DU=du
EGREP=egrep
GZIP=gzip
FIND=find
FUSER=fuser
HEAD=head
HOSTNAME=hostname
LS=ls
PERL=perl
PRINTF=printf
RM=rm
SED=sed
SYNC=sync
SORT=sort
UNIQ=uniq
WC=wc

GLOBAL_EXEMPTION_LIST='
	GLOBAL_DIR_QUEUE
	GLOBAL_FILE_PATTERN
'

GLOBAL_DIRECTIVE_LIST='
	GLOBAL_RET_DELETE
	GLOBAL_RET_COMPRESS
	GLOBAL_DRY_RUN
	GLOBAL_CHILD_PROCESS
	GLOBAL_PARALLEL_BIN
	GLOBAL_NICENESS
	GLOBAL_RECURSIVE
	GLOBAL_SUDO_BIN
	GLOBAL_USE_SUDO
	GLOBAL_ENABLED
	GLOBAL_VERBOSE_LOGGING
	GLOBAL_FLUSH
	GLOBAL_USER
	GLOBAL_DIR_QUEUE
	GLOBAL_FILE_PATTERN
'

#==============================================================================
#set -vx

CUR_DIR="$($DIRNAME $0)"
CONFIG_FILE="$CUR_DIR"/"$CONFIG_FILE"

: ${JOB_COUNTER:=0}

# default definitions if not explicitly defined
[[ -n "$LOGNAME" ]] && : ${GLOBAL_USER:=$LOGNAME}
: ${GLOBAL_DRY_RUN:=false}
: ${GLOBAL_CHILD_PROCESS:=4}
: ${GLOBAL_NICENESS:=19}
: ${GLOBAL_RECURSIVE:=false}
: ${GLOBAL_SUDO_BIN:=sudo}
: ${GLOBAL_USE_SUDO:=false}
: ${GLOBAL_ENABLED:=true}
: ${GLOBAL_VERBOSE_LOGGING:=0}
: ${GLOBAL_FLUSH:=true}

# save the default IFS
save_ifs

case "$1" in
	-f|--first-time)
				first_time
				;;
	-j|--execute-job) 
				execute_job
				unset_job_def
				;;
	-l|--last-time) 
				last_time
	   			exit 0
				;;
esac

if [[ "$#" -eq 0 ]]; then
	# at this point, we assume that run.sh has been invoked directly

	export PATH=/usr/bin:/bin:/usr/sbin:$PATH

	# let's load the configuration file
	if [[ ! -r "$CONFIG_FILE" ]]; then
		printf "<$($DATE "+%b %d, %Y %T %p %Z")> <Error> <$($HOSTNAME)> <$($BASENAME $0)> \
Fatal error occurred: cannot access \"$CONFIG_FILE\".\n" >&2
		exit 1
	else
		. "$CONFIG_FILE"
	fi
fi
