#!/usr/bin/perl
#
# Author: Patricia Wilthew
#
# Description: Perl script to get an accurate amount of free space present on flash  
# array storage for planning purposes 
#
# Process:
# 1. Checks the output of lsmod for the presence of vmw_pvscsi to determine if
#     the computer is a virtual machine. If it is not, exit the program
# 2. Gets all local file systems
# 3. Gets available and use% space on each file system
# 4. If the available space is less than 1Gb or the use% is over 95%, skip
# 5. If the available space is more than 1Gb, write zeroes to the file system
#     for all but 1Gb of free space.

my $lsmod = `lsmod | grep pvscsi`;

if ($lsmod eq "") {

	print "Error: This system is not a virtual machine\n";
	exit;
}

my @local_fs = split("\n", `mount | egrep "xfs|ext"`);

for (my $i = 0; $i < @local_fs; $i++) {

	my $flag = 0;
	my $partition_name = ((split(" ", $local_fs[$i]))[0]);
	my $mount_point = ((split(" ", $local_fs[$i]))[2]);

    print "\n---Mount point: $mount_point\n";

	if ((substr($partition_name,0,1)) eq "/") {  #only partitions which names start with a slash
	
		my ($available, $use) = get_usage($partition_name);

		print "Partition: $partition_name\n";

		if ($available <= 1048576) { #1 GB
			
			print "Available: $available <----WARNING: Less than 1GB\n";
		}
		else {
			
			print "Available: $available\n";
			$flag = 1;
		}

		if ($use >= 95) {

			print "Use: $use <----WARNING: Over 95%\n";
			$flag = 0;
		}
		else {
			
			print "Use: $use\n";
		}
	}
	else { #ignore file systems which names do not start with a slash
		next;
	}


	if ($flag==1) {
		
		write_zeroes($partition_name, $mount_point);
	}
}

# Function get_usage
# Given the name of a disk partition, outputs its available space
# and use%
#
sub get_usage($) {

	my $partition = shift;	

	my $command = `df -k $partition`;
	
	my $available = (split(" ", (split("\n", $command))[1]))[3];
	my $use = (split(" ", (split("\n", $command))[1]))[4];

	return ($available, $use);
}

# Function write_zeroes
# Given the name of a disk partition and its mount point, writes
# zeros to the file system for all but 1Gb of free space
#
sub write_zeroes {

	my $partition = shift;
	my $mount_point = shift;

    my $available = (split(" ", (split("\n", `df -k $partition`))[1]))[3];
	
	my $remainder = $available-1048576; #1 GB

    if ($mount_point eq "/") { $mount_point = ""; }

	print "Zeroing $mount_point with $remainder blocks...\n";
	print `dd if=/dev/zero of=$mount_point/zerofile bs=1024 count=$remainder; sync; rm -f $mount_point/zerofile`;
	
}
