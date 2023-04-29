#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <png.h>

png_bytep *rows;

void read_file(char* in) {
	FILE *fp = fopen(in, "rb");
	png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	png_infop info = png_create_info_struct(png);
	png_init_io(png, fp);
	png_read_info(png, info);
	int width = png_get_image_width(png, info);
	int height = png_get_image_height(png, info);
	if (!(width == 256 && height == 256)) {
		printf("%s must be 256 x 256\n", in);
		exit(1);
	}
	png_byte bit_depth = png_get_bit_depth(png, info);
	if (bit_depth != 8) {
		printf("%s must be 8 bit depth\n", in);
		exit(1);
	}
	png_byte color_type = png_get_color_type(png, info);
	if (color_type != PNG_COLOR_TYPE_RGB) {
		printf("%s must be RGB\n", in);
		exit(1);
	}
	rows = (png_bytep*) malloc(sizeof(png_bytep)*256);
	for (int y=0; y<256; y++) {
		rows[y] = (png_byte*) malloc(png_get_rowbytes(png, info));
	}
	png_read_image(png, rows);
	fclose(fp);
}

void encode() {
	char message[256] = {0};
	printf("message (less than 256 bytes): ");
	fgets(message, sizeof(message), stdin);
	for (int y=0; y<256; y++) {
		png_bytep row = rows[y];
		for (int x=0; x<256; x++) {
			png_bytep pixel = &(row[x*3]);
			pixel[0] ^= rand() & 1;
			pixel[1] ^= rand() & 1;
			pixel[2] ^= rand() & 1;
		}
		for (int i=0; i<8; i++) {
			png_bytep pixel = &(row[i*32*3]);
			int b = (message[y] >> i) & 1;
			if (pixel[2] & 1) {
				pixel[2] ^= 1;
			}
			pixel[2] |= (pixel[0] & 1) ^ (pixel[1] & 1) ^ b;
		}
	}
}

void write_file(char* out) {
	FILE *fp = fopen(out, "wb");
	png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	png_infop info = png_create_info_struct(png);
	png_init_io(png, fp);
	png_set_IHDR(png, info, 256, 256, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
	png_write_info(png, info);
	png_write_image(png, rows);
	png_write_end(png, NULL);
	fclose(fp);
}

int main(int argc, char **argv) {
	if (argc != 3) {
		printf("USAGE: %s in.png out.png\n", argv[0]);
		exit(1);
	}
	srand(time(0));
	read_file(argv[1]);
	encode();
	write_file(argv[2]);
	return 0;
}