#include "output_helpers.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

void my_print(FILE *fp, bool isenter, const char *format, ...){
	char buffer[100]={};
	va_list args;
	va_start(args, format);

	vsnprintf(buffer, sizeof(buffer), format, args);

	va_end(args);
	
	if(isenter){
		if(fp)
    		fprintf(fp, "%s\n", buffer);
		else
			printf("%s\n", buffer);
	}
	else{
		if(fp)
    		fprintf(fp, "%s", buffer);
		else
			printf("%s", buffer);
	}
	
}

static void get_stars(char *stars, unsigned int val, unsigned int val_max, int width)
{
	int num_stars, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
    	stars[i] = '*';
    for (i; i < width; i++)
    	stars[i] = ' ';
    if (need_plus)
    	stars[i++] = '+';
	stars[i]='\0';
}

void print_log2_hist(unsigned int total, unsigned int *vals, int vals_size, const char *val_type, FILE *fp){
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int width, i;
	char stars[41] = {};

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;


    my_print(fp, "%*s%-*s : count    distribution", idx_max <= 32 ? 5 : 15, "",
    		idx_max <= 32 ? 19 : 29, val_type);
	
	if (idx_max > 32)
		stars_max = stars_max / 2;

	for (i = 0; i <= idx_max; i++) {
		val = vals[i];
		if (!val)
			continue;
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		width = idx_max <= 32 ? 10 : 20;
		get_stars(stars, val, val_max, stars_max);
    	my_print(fp, "%*lld -> %-*lld : %-8d |%s|%.2f%%", width, low, width, high, val, stars, (double)val / (double)total*100);
	}
}

void print_linear_hist(unsigned int total, unsigned int *vals, int vals_size, unsigned int base,
		       unsigned int step, const char *val_type, FILE *fp){
	char stars[41] = {};
	int i, stars_max = 40, idx_min = -1, idx_max = -1;
	unsigned int val, val_max = 0;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0) {
			idx_max = i;
			if (idx_min < 0)
				idx_min = i;
		}
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

    my_print(fp, "     %-13s : count     distribution", val_type);
	for (i = idx_min; i <= idx_max; i++) {
		val = vals[i];
		if (!val)
			continue;
    	get_stars(stars, val, val_max, stars_max);
		my_print(fp, "        %-10d : %-8d |%s|%.2f%%", base + i * step, val, stars, (double)val / (double)total*100);
	}
}
