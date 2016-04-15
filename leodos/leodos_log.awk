BEGIN {
	#output_file="./result/leodos_log.rs";
	output_file="./leodos_log.rs";
	#print "TitleText: leodos" >> output_file;
	#print "Device: Postscript" >> output_file;	
	#print "\"r_rate_attack" >> output_file;
	f1_ps = 1040;
	f2_ps = 50;
	sp = ","
}
function calMbps(p_rate, p_size){
	p_mpbs = (p_rate * p_size * 8) / 1024 / 1024;
	return p_mpbs;
}
$0 ~/ak_pr/ {
	printf $2 sp >> output_file;
}
$1 ~/bn_qm/ {
	printf $2 sp >> output_file;
}
$5 ~/\*>\*/ {
	printf $6 sp >> output_file;
	printf $7 sp >> output_file;
	printf $9 sp >> output_file;
}
$1 ~/r_rate_f1_normal/ {
	printf $2 sp calMbps($2, f1_ps) sp >> output_file;
	printf $4 sp calMbps($4, f1_ps) sp >> output_file;
	printf $6 sp >> output_file;
}
$1 ~/r_rate_f2_normal/ {
	printf $4 sp calMbps($4, f2_ps) sp >> output_file;
	printf "\n" >> output_file;
}
END {	
}
