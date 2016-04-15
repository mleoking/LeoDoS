BEGIN {
	f_out_ml="./result/leodos_log.m";
	maxn=0;

	ak_n[maxn]=0;
	ak_ap[maxn]=0;
	ak_bp[maxn]=0;
	ak_pr[maxn]=0;
	
	bn_qm[maxn]=0;


	rate_f1_normal[maxn]=0;
	rate_f1_attack[maxn]=0;
	nth_f1[maxn]=0;
	rate_f2_normal[maxn]=0;
	rate_f2_attack[maxn]=0;
	nth_f2[maxn]=0;

	r_rate_f1_normal[maxn]=0;
	r_rate_f1_attack[maxn]=0;
	r_nth_f1[maxn]=0;
	r_rate_f2_normal[maxn]=0;
	r_rate_f2_attack[maxn]=0;
	r_nth_f2[maxn]=0;
	
	#variables for IIA
	afr_f1[maxn]=0;
	afr_f2[maxn]=0;
	t_de_from[maxn]=10000;
	t_de_to[maxn]=-1;
}
function str2number(str, spliter){
	rtn = -1;
	split(str, strs, spliter);
	if (strs[2] != "") {
		rtn = 0 + strs[2];
	}
	return rtn;
}
function output_array(type, f_out, arrayname, array, ib, ie){
	printf "%s = [ ", arrayname >> f_out;
	for (i=ib; i<=ie; i++){
		if (type=="float") {
			printf "%.2f ", array[i] >> f_out;	
		}
		if (type=="int") {
			printf "%d ", array[i] >> f_out;
		}
	}
	printf "];\n", arrayname >> f_out;
}
function output(){
	output_array("int", f_out_ml, "ak_n", ak_n, 1, maxn);
	output_array("float", f_out_ml, "ak_ap", ak_ap, 1, maxn);
	output_array("float", f_out_ml, "ak_bp", ak_bp, 1, maxn);
	output_array("float", f_out_ml, "ak_pr", ak_pr, 1, maxn);
	
	output_array("int", f_out_ml, "bn_qm", bn_qm, 1, maxn);

	output_array("float", f_out_ml, "rate_f1_normal", rate_f1_normal, 1, maxn);
	output_array("float", f_out_ml, "rate_f1_attack", rate_f1_attack, 1, maxn);
	output_array("float", f_out_ml, "nth_f1", nth_f1, 1, maxn);

	output_array("float", f_out_ml, "rate_f2_normal", rate_f2_normal, 1, maxn);
	output_array("float", f_out_ml, "rate_f2_attack", rate_f2_attack, 1, maxn);
	output_array("float", f_out_ml, "nth_f2", nth_f2, 1, maxn);

	output_array("float", f_out_ml, "r_rate_f1_normal", r_rate_f1_normal, 1, maxn);
	output_array("float", f_out_ml, "r_rate_f1_attack", r_rate_f1_attack, 1, maxn);
	output_array("float", f_out_ml, "r_nth_f1", r_nth_f1, 1, maxn);

	output_array("float", f_out_ml, "r_rate_f2_normal", r_rate_f2_normal, 1, maxn);
	output_array("float", f_out_ml, "r_rate_f2_attack", r_rate_f2_attack, 1, maxn);
	output_array("float", f_out_ml, "r_nth_f2", r_nth_f2, 1, maxn);
}
{
	if ($1 == "li") {
		maxn++;
		t_de_from[maxn]=10000;
		t_de_to[maxn]=-1;
	}
	if ($1 == "ak_bp") {
		ak_bp[maxn]=$2;
	}
	if ($1 == "ak_pr") {
		ak_pr[maxn]=$2;
	}
	if ($1 == "ak_n") {
		ak_n[maxn]=$2;
	}
	if ($1 == "ak_ap") {
		ak_ap[maxn]=$2;
	}
	
	if ($1 == "bn_qm") {
		bn_qm[maxn]=$2;
	}
	
	if ($1 == "rate_f1_normal") {
		rate_f1_normal[maxn]=$2;
		rate_f1_attack[maxn]=$4;
		nth_f1[maxn]=$6;
	}
	if ($1 == "rate_f2_normal") {
		rate_f2_normal[maxn]=$2;
		rate_f2_attack[maxn]=$4;
		nth_f2[maxn]=$6;
	}
	if ($1 == "r_rate_f1_normal") {
		r_rate_f1_normal[maxn]=$2;
		r_rate_f1_attack[maxn]=$4;
		r_nth_f1[maxn]=$6;
	}
	if ($1 == "r_rate_f2_normal") {
		r_rate_f2_normal[maxn]=$2;
		r_rate_f2_attack[maxn]=$4;
		r_nth_f2[maxn]=$6;
	}
}						  
END {
	output();
}
