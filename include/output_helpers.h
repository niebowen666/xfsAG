#ifndef __OUTPUT_HELPERS_H
#define __OUTPUT_HELPERS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void my_print(FILE *fp, bool isenter, const char *format, ...);
static void get_stars(char *stars, unsigned int val, unsigned int val_max, int width);
void print_log2_hist(unsigned int total, unsigned int *vals, int vals_size, const char *val_type, FILE *fp);
void print_linear_hist(unsigned int total, unsigned int *vals, int vals_size, unsigned int base, unsigned int step, const char *val_type, FILE *fp);

#endif
