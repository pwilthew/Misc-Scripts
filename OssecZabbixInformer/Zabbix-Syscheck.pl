#!/usr/bin/perl
## cronjob
##
## Compares the current time with the last time the ossec
## syscheck process ran in every agent. If it has been more
## than 60 minutes (assuming that Ossec syscheck will be set to 
## run every 30 minutes), do not send a "0" signal to Zabbix
## but log it in /var/log/messages. Zabbix will then realize
## that it did not receive a "0" within an interval of time,
## and trigger an alarm. 
##
## Script assumes the Zabbix trapper (item) Key is "trapper.ossec.informer"
## and the Trigger's expression is `{host.name:trapper.ossec.informer.nodata(30m)}=1`
##
## Cronjob should be set to run every 30 minutes
##
use Sys::Syslog qw(:DEFAULT setlogsock);
use File::Basename;

# Get current time
my $current_date = `date`;
my $current_time = (split(' ', $current_date))[3];
my $current_time_to_number = time_to_number(split(':', $current_time));

# Get agents IDs
my $agents = `/var/ossec/bin/manage_agents -l`;

my @agents_list = split("\n", $agents);			#create an array of lines

foreach my $line (@agents_list) { $line =~ s/^\s+//; }	#remove leading spaces

@agents_list = grep { /^ID/ } @agents_list;		#keep lines which start with ID

foreach my $line (@agents_list) {

	$line = (split (/\s/, $line))[1];		#keep the id number
	$line = (split (/,/, $line))[0];		#remove commas
}

# Check
foreach my $agent (@agents_list) {

	# Get last time that syscheck ran
	my @command = `/var/ossec/bin/agent_control -i $agent`;
	my $last_time = (split(' ', $command[11]))[7];
	my $last_time_to_number = time_to_number(split(':', $last_time));

	# To include cases when current_time is, for example 00:30 and last_time is 23:58
	if (($current_time_to_number - $last_time_to_number)<0)
        {
	        $current_time_to_number += 60*24; #add 24h (in minutes)
        }   
	# If it has been more than 60 minutes since a syscheck was performed, exit and do not report Zabbix
	if (($current_time_to_number - $last_time_to_number)>60)
	{
		setlogsock("unix");
		openlog(basename($0), "pid,nowait,nonul,noeol,perror");
		syslog("warning", "Alert: Ossec-syscheck has not been running within the past 60 minutes in agent $agent");
		closelog();
		exit;
	}

	# Send alive signal, or "0", to Zabbix server
	`zabbix_sender --zabbix-server=<Write Zabbix Server IP here> --port=10051 --host="<Write host.name here>" --key="trapper.ossec.informer" --value="0"`;

}



# Converts a time string into a integer (in minutes)
sub time_to_number{

	my @array = @_;
	return $array[0]*60 + $array[1] + $array[2]/60;

}
