;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module aes256
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _aes256_encrypt
	.globl _puts
	.globl _printf
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _DATA
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _INITIALIZED
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area _DABS (ABS)
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area _HOME
	.area _GSINIT
	.area _GSFINAL
	.area _GSINIT
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area _HOME
	.area _HOME
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area _CODE
	Faes256$xtime$0$0	= .
	.globl	Faes256$xtime$0$0
	C$aes256.c$38$0_0$35	= .
	.globl	C$aes256.c$38$0_0$35
;/work/source_code/aes256.c:38: static uint8_t xtime(uint8_t x) {
;	---------------------------------
; Function xtime
; ---------------------------------
_xtime:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes256.c$39$1_0$35	= .
	.globl	C$aes256.c$39$1_0$35
;/work/source_code/aes256.c:39: return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
	ld	a, 4 (ix)
	add	a, a
	ld	c, a
	ld	a, 4 (ix)
	rlc	a
	and	a, #0x01
	ld	e, a
	ld	d, #0x00
	ld	l, e
	ld	h, d
	add	hl, hl
	add	hl, de
	add	hl, hl
	add	hl, hl
	add	hl, de
	add	hl, hl
	add	hl, de
	ld	a, c
	rla
	sbc	a, a
	push	af
	ld	a, c
	xor	a, l
	ld	l, a
	pop	af
	xor	a, h
	C$aes256.c$40$1_0$35	= .
	.globl	C$aes256.c$40$1_0$35
;/work/source_code/aes256.c:40: }
	pop	ix
	C$aes256.c$40$1_0$35	= .
	.globl	C$aes256.c$40$1_0$35
	XFaes256$xtime$0$0	= .
	.globl	XFaes256$xtime$0$0
	ret
Faes256$sbox$0_0$0 == .
_sbox:
	.db #0x63	; 99	'c'
	.db #0x7c	; 124
	.db #0x77	; 119	'w'
	.db #0x7b	; 123
	.db #0xf2	; 242
	.db #0x6b	; 107	'k'
	.db #0x6f	; 111	'o'
	.db #0xc5	; 197
	.db #0x30	; 48	'0'
	.db #0x01	; 1
	.db #0x67	; 103	'g'
	.db #0x2b	; 43
	.db #0xfe	; 254
	.db #0xd7	; 215
	.db #0xab	; 171
	.db #0x76	; 118	'v'
	.db #0xca	; 202
	.db #0x82	; 130
	.db #0xc9	; 201
	.db #0x7d	; 125
	.db #0xfa	; 250
	.db #0x59	; 89	'Y'
	.db #0x47	; 71	'G'
	.db #0xf0	; 240
	.db #0xad	; 173
	.db #0xd4	; 212
	.db #0xa2	; 162
	.db #0xaf	; 175
	.db #0x9c	; 156
	.db #0xa4	; 164
	.db #0x72	; 114	'r'
	.db #0xc0	; 192
	.db #0xb7	; 183
	.db #0xfd	; 253
	.db #0x93	; 147
	.db #0x26	; 38
	.db #0x36	; 54	'6'
	.db #0x3f	; 63
	.db #0xf7	; 247
	.db #0xcc	; 204
	.db #0x34	; 52	'4'
	.db #0xa5	; 165
	.db #0xe5	; 229
	.db #0xf1	; 241
	.db #0x71	; 113	'q'
	.db #0xd8	; 216
	.db #0x31	; 49	'1'
	.db #0x15	; 21
	.db #0x04	; 4
	.db #0xc7	; 199
	.db #0x23	; 35
	.db #0xc3	; 195
	.db #0x18	; 24
	.db #0x96	; 150
	.db #0x05	; 5
	.db #0x9a	; 154
	.db #0x07	; 7
	.db #0x12	; 18
	.db #0x80	; 128
	.db #0xe2	; 226
	.db #0xeb	; 235
	.db #0x27	; 39
	.db #0xb2	; 178
	.db #0x75	; 117	'u'
	.db #0x09	; 9
	.db #0x83	; 131
	.db #0x2c	; 44
	.db #0x1a	; 26
	.db #0x1b	; 27
	.db #0x6e	; 110	'n'
	.db #0x5a	; 90	'Z'
	.db #0xa0	; 160
	.db #0x52	; 82	'R'
	.db #0x3b	; 59
	.db #0xd6	; 214
	.db #0xb3	; 179
	.db #0x29	; 41
	.db #0xe3	; 227
	.db #0x2f	; 47
	.db #0x84	; 132
	.db #0x53	; 83	'S'
	.db #0xd1	; 209
	.db #0x00	; 0
	.db #0xed	; 237
	.db #0x20	; 32
	.db #0xfc	; 252
	.db #0xb1	; 177
	.db #0x5b	; 91
	.db #0x6a	; 106	'j'
	.db #0xcb	; 203
	.db #0xbe	; 190
	.db #0x39	; 57	'9'
	.db #0x4a	; 74	'J'
	.db #0x4c	; 76	'L'
	.db #0x58	; 88	'X'
	.db #0xcf	; 207
	.db #0xd0	; 208
	.db #0xef	; 239
	.db #0xaa	; 170
	.db #0xfb	; 251
	.db #0x43	; 67	'C'
	.db #0x4d	; 77	'M'
	.db #0x33	; 51	'3'
	.db #0x85	; 133
	.db #0x45	; 69	'E'
	.db #0xf9	; 249
	.db #0x02	; 2
	.db #0x7f	; 127
	.db #0x50	; 80	'P'
	.db #0x3c	; 60
	.db #0x9f	; 159
	.db #0xa8	; 168
	.db #0x51	; 81	'Q'
	.db #0xa3	; 163
	.db #0x40	; 64
	.db #0x8f	; 143
	.db #0x92	; 146
	.db #0x9d	; 157
	.db #0x38	; 56	'8'
	.db #0xf5	; 245
	.db #0xbc	; 188
	.db #0xb6	; 182
	.db #0xda	; 218
	.db #0x21	; 33
	.db #0x10	; 16
	.db #0xff	; 255
	.db #0xf3	; 243
	.db #0xd2	; 210
	.db #0xcd	; 205
	.db #0x0c	; 12
	.db #0x13	; 19
	.db #0xec	; 236
	.db #0x5f	; 95
	.db #0x97	; 151
	.db #0x44	; 68	'D'
	.db #0x17	; 23
	.db #0xc4	; 196
	.db #0xa7	; 167
	.db #0x7e	; 126
	.db #0x3d	; 61
	.db #0x64	; 100	'd'
	.db #0x5d	; 93
	.db #0x19	; 25
	.db #0x73	; 115	's'
	.db #0x60	; 96
	.db #0x81	; 129
	.db #0x4f	; 79	'O'
	.db #0xdc	; 220
	.db #0x22	; 34
	.db #0x2a	; 42
	.db #0x90	; 144
	.db #0x88	; 136
	.db #0x46	; 70	'F'
	.db #0xee	; 238
	.db #0xb8	; 184
	.db #0x14	; 20
	.db #0xde	; 222
	.db #0x5e	; 94
	.db #0x0b	; 11
	.db #0xdb	; 219
	.db #0xe0	; 224
	.db #0x32	; 50	'2'
	.db #0x3a	; 58
	.db #0x0a	; 10
	.db #0x49	; 73	'I'
	.db #0x06	; 6
	.db #0x24	; 36
	.db #0x5c	; 92
	.db #0xc2	; 194
	.db #0xd3	; 211
	.db #0xac	; 172
	.db #0x62	; 98	'b'
	.db #0x91	; 145
	.db #0x95	; 149
	.db #0xe4	; 228
	.db #0x79	; 121	'y'
	.db #0xe7	; 231
	.db #0xc8	; 200
	.db #0x37	; 55	'7'
	.db #0x6d	; 109	'm'
	.db #0x8d	; 141
	.db #0xd5	; 213
	.db #0x4e	; 78	'N'
	.db #0xa9	; 169
	.db #0x6c	; 108	'l'
	.db #0x56	; 86	'V'
	.db #0xf4	; 244
	.db #0xea	; 234
	.db #0x65	; 101	'e'
	.db #0x7a	; 122	'z'
	.db #0xae	; 174
	.db #0x08	; 8
	.db #0xba	; 186
	.db #0x78	; 120	'x'
	.db #0x25	; 37
	.db #0x2e	; 46
	.db #0x1c	; 28
	.db #0xa6	; 166
	.db #0xb4	; 180
	.db #0xc6	; 198
	.db #0xe8	; 232
	.db #0xdd	; 221
	.db #0x74	; 116	't'
	.db #0x1f	; 31
	.db #0x4b	; 75	'K'
	.db #0xbd	; 189
	.db #0x8b	; 139
	.db #0x8a	; 138
	.db #0x70	; 112	'p'
	.db #0x3e	; 62
	.db #0xb5	; 181
	.db #0x66	; 102	'f'
	.db #0x48	; 72	'H'
	.db #0x03	; 3
	.db #0xf6	; 246
	.db #0x0e	; 14
	.db #0x61	; 97	'a'
	.db #0x35	; 53	'5'
	.db #0x57	; 87	'W'
	.db #0xb9	; 185
	.db #0x86	; 134
	.db #0xc1	; 193
	.db #0x1d	; 29
	.db #0x9e	; 158
	.db #0xe1	; 225
	.db #0xf8	; 248
	.db #0x98	; 152
	.db #0x11	; 17
	.db #0x69	; 105	'i'
	.db #0xd9	; 217
	.db #0x8e	; 142
	.db #0x94	; 148
	.db #0x9b	; 155
	.db #0x1e	; 30
	.db #0x87	; 135
	.db #0xe9	; 233
	.db #0xce	; 206
	.db #0x55	; 85	'U'
	.db #0x28	; 40
	.db #0xdf	; 223
	.db #0x8c	; 140
	.db #0xa1	; 161
	.db #0x89	; 137
	.db #0x0d	; 13
	.db #0xbf	; 191
	.db #0xe6	; 230
	.db #0x42	; 66	'B'
	.db #0x68	; 104	'h'
	.db #0x41	; 65	'A'
	.db #0x99	; 153
	.db #0x2d	; 45
	.db #0x0f	; 15
	.db #0xb0	; 176
	.db #0x54	; 84	'T'
	.db #0xbb	; 187
	.db #0x16	; 22
Faes256$rcon$0_0$0 == .
_rcon:
	.db #0x00	; 0
	.db #0x01	; 1
	.db #0x02	; 2
	.db #0x04	; 4
	.db #0x08	; 8
	.db #0x10	; 16
	.db #0x20	; 32
	.db #0x40	; 64
	.db #0x80	; 128
	.db #0x1b	; 27
	.db #0x36	; 54	'6'
	.db #0x6c	; 108	'l'
	.db #0xd8	; 216
	.db #0xab	; 171
	.db #0x4d	; 77	'M'
	Faes256$sub_bytes$0$0	= .
	.globl	Faes256$sub_bytes$0$0
	C$aes256.c$42$1_0$38	= .
	.globl	C$aes256.c$42$1_0$38
;/work/source_code/aes256.c:42: static void sub_bytes(uint8_t *state) {
;	---------------------------------
; Function sub_bytes
; ---------------------------------
_sub_bytes:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes256.c$43$3_0$39	= .
	.globl	C$aes256.c$43$3_0$39
;/work/source_code/aes256.c:43: for (int i = 0; i < 16; i++) {
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00105$
	C$aes256.c$44$3_0$39	= .
	.globl	C$aes256.c$44$3_0$39
;/work/source_code/aes256.c:44: state[i] = sbox[state[i]];
	ld	a, 4 (ix)
	add	a, c
	ld	e, a
	ld	a, 5 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	C$aes256.c$43$2_0$38	= .
	.globl	C$aes256.c$43$2_0$38
;/work/source_code/aes256.c:43: for (int i = 0; i < 16; i++) {
	inc	bc
	jr	00103$
00105$:
	C$aes256.c$46$2_0$38	= .
	.globl	C$aes256.c$46$2_0$38
;/work/source_code/aes256.c:46: }
	pop	ix
	C$aes256.c$46$2_0$38	= .
	.globl	C$aes256.c$46$2_0$38
	XFaes256$sub_bytes$0$0	= .
	.globl	XFaes256$sub_bytes$0$0
	ret
	Faes256$shift_rows$0$0	= .
	.globl	Faes256$shift_rows$0$0
	C$aes256.c$48$2_0$41	= .
	.globl	C$aes256.c$48$2_0$41
;/work/source_code/aes256.c:48: static void shift_rows(uint8_t *state) {
;	---------------------------------
; Function shift_rows
; ---------------------------------
_shift_rows:
	push	ix
	ld	ix,#0
	add	ix,sp
	dec	sp
	C$aes256.c$51$1_0$41	= .
	.globl	C$aes256.c$51$1_0$41
;/work/source_code/aes256.c:51: temp = state[1];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	ld	a, (de)
	ld	-1 (ix), a
	C$aes256.c$52$1_0$41	= .
	.globl	C$aes256.c$52$1_0$41
;/work/source_code/aes256.c:52: state[1] = state[5];
	ld	a, 4 (ix)
	add	a, #0x05
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, (bc)
	ld	(de), a
	C$aes256.c$53$1_0$41	= .
	.globl	C$aes256.c$53$1_0$41
;/work/source_code/aes256.c:53: state[5] = state[9];
	ld	a, 4 (ix)
	add	a, #0x09
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	a, (de)
	ld	(bc), a
	C$aes256.c$54$1_0$41	= .
	.globl	C$aes256.c$54$1_0$41
;/work/source_code/aes256.c:54: state[9] = state[13];
	ld	a, 4 (ix)
	add	a, #0x0d
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, (bc)
	ld	(de), a
	C$aes256.c$55$1_0$41	= .
	.globl	C$aes256.c$55$1_0$41
;/work/source_code/aes256.c:55: state[13] = temp;
	ld	a, -1 (ix)
	ld	(bc), a
	C$aes256.c$57$1_0$41	= .
	.globl	C$aes256.c$57$1_0$41
;/work/source_code/aes256.c:57: temp = state[2];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	inc	de
	ld	a, (de)
	ld	-1 (ix), a
	C$aes256.c$58$1_0$41	= .
	.globl	C$aes256.c$58$1_0$41
;/work/source_code/aes256.c:58: state[2] = state[10];
	ld	a, 4 (ix)
	add	a, #0x0a
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, (bc)
	ld	(de), a
	C$aes256.c$59$1_0$41	= .
	.globl	C$aes256.c$59$1_0$41
;/work/source_code/aes256.c:59: state[10] = temp;
	ld	a, -1 (ix)
	ld	(bc), a
	C$aes256.c$60$1_0$41	= .
	.globl	C$aes256.c$60$1_0$41
;/work/source_code/aes256.c:60: temp = state[6];
	ld	a, 4 (ix)
	add	a, #0x06
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	a, (de)
	ld	-1 (ix), a
	C$aes256.c$61$1_0$41	= .
	.globl	C$aes256.c$61$1_0$41
;/work/source_code/aes256.c:61: state[6] = state[14];
	ld	a, 4 (ix)
	add	a, #0x0e
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, (bc)
	ld	(de), a
	C$aes256.c$62$1_0$41	= .
	.globl	C$aes256.c$62$1_0$41
;/work/source_code/aes256.c:62: state[14] = temp;
	ld	a, -1 (ix)
	ld	(bc), a
	C$aes256.c$64$1_0$41	= .
	.globl	C$aes256.c$64$1_0$41
;/work/source_code/aes256.c:64: temp = state[15];
	ld	a, 4 (ix)
	add	a, #0x0f
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	a, (de)
	ld	-1 (ix), a
	C$aes256.c$65$1_0$41	= .
	.globl	C$aes256.c$65$1_0$41
;/work/source_code/aes256.c:65: state[15] = state[11];
	ld	a, 4 (ix)
	add	a, #0x0b
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, (bc)
	ld	(de), a
	C$aes256.c$66$1_0$41	= .
	.globl	C$aes256.c$66$1_0$41
;/work/source_code/aes256.c:66: state[11] = state[7];
	ld	a, 4 (ix)
	add	a, #0x07
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	a, (de)
	ld	(bc), a
	C$aes256.c$67$1_0$41	= .
	.globl	C$aes256.c$67$1_0$41
;/work/source_code/aes256.c:67: state[7] = state[3];
	ld	c, 4 (ix)
	ld	b, 5 (ix)
	inc	bc
	inc	bc
	inc	bc
	ld	a, (bc)
	ld	(de), a
	C$aes256.c$68$1_0$41	= .
	.globl	C$aes256.c$68$1_0$41
;/work/source_code/aes256.c:68: state[3] = temp;
	ld	a, -1 (ix)
	ld	(bc), a
	C$aes256.c$69$1_0$41	= .
	.globl	C$aes256.c$69$1_0$41
;/work/source_code/aes256.c:69: }
	inc	sp
	pop	ix
	C$aes256.c$69$1_0$41	= .
	.globl	C$aes256.c$69$1_0$41
	XFaes256$shift_rows$0$0	= .
	.globl	XFaes256$shift_rows$0$0
	ret
	Faes256$mix_columns$0$0	= .
	.globl	Faes256$mix_columns$0$0
	C$aes256.c$71$1_0$43	= .
	.globl	C$aes256.c$71$1_0$43
;/work/source_code/aes256.c:71: static void mix_columns(uint8_t *state) {
;	---------------------------------
; Function mix_columns
; ---------------------------------
_mix_columns:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-30
	add	hl, sp
	ld	sp, hl
	C$aes256.c$74$3_0$45	= .
	.globl	C$aes256.c$74$3_0$45
;/work/source_code/aes256.c:74: for (int i = 0; i < 4; i++) {
	ld	hl, #2
	add	hl, sp
	ld	-12 (ix), l
	ld	-11 (ix), h
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00101$
	C$aes256.c$75$3_0$45	= .
	.globl	C$aes256.c$75$3_0$45
;/work/source_code/aes256.c:75: int idx = i * 4;
	ld	e, c
	ld	d, b
	sla	e
	rl	d
	sla	e
	rl	d
	C$aes256.c$76$3_0$45	= .
	.globl	C$aes256.c$76$3_0$45
;/work/source_code/aes256.c:76: tmp[idx + 0] = (uint8_t)(xtime(state[idx + 0]) ^ xtime(state[idx + 1]) ^ state[idx + 1] ^ state[idx + 2] ^ state[idx + 3]);
	ld	-10 (ix), e
	ld	a, e
	ld	l, a
	rla
	sbc	a, a
	ld	h, a
	ld	a, l
	add	a, -12 (ix)
	ld	-30 (ix), a
	ld	a, h
	adc	a, -11 (ix)
	ld	-29 (ix), a
	ld	a, 4 (ix)
	add	a, e
	ld	-9 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-8 (ix), a
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	-3 (ix), l
	pop	de
	pop	bc
	ld	hl, #0x0001
	add	hl, de
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -2 (ix)
	add	a, 4 (ix)
	ld	-7 (ix), a
	ld	a, -1 (ix)
	adc	a, 5 (ix)
	ld	-6 (ix), a
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -3 (ix)
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	l, (hl)
	xor	a, l
	ld	-1 (ix), a
	ld	hl, #0x0002
	add	hl, de
	ld	-3 (ix), l
	ld	-2 (ix), h
	ld	a, -3 (ix)
	add	a, 4 (ix)
	ld	-5 (ix), a
	ld	a, -2 (ix)
	adc	a, 5 (ix)
	ld	-4 (ix), a
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	-1 (ix), a
	inc	de
	inc	de
	inc	de
	ld	a, e
	add	a, 4 (ix)
	ld	-3 (ix), a
	ld	a, d
	adc	a, 5 (ix)
	ld	-2 (ix), a
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	a, (hl)
	xor	a, -1 (ix)
	pop	hl
	push	hl
	ld	(hl), a
	C$aes256.c$77$3_0$45	= .
	.globl	C$aes256.c$77$3_0$45
;/work/source_code/aes256.c:77: tmp[idx + 1] = (uint8_t)(state[idx + 0] ^ xtime(state[idx + 1]) ^ xtime(state[idx + 2]) ^ state[idx + 2] ^ state[idx + 3]);
	ld	a, -10 (ix)
	inc	a
	ld	e, a
	rla
	sbc	a, a
	ld	d, a
	ld	a, e
	add	a, -12 (ix)
	ld	e, a
	ld	a, d
	adc	a, -11 (ix)
	ld	d, a
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	ld	a, (hl)
	ld	-1 (ix), a
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -1 (ix)
	ld	-1 (ix), a
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -1 (ix)
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	l, (hl)
	xor	a, l
	ld	(de), a
	C$aes256.c$78$3_0$45	= .
	.globl	C$aes256.c$78$3_0$45
;/work/source_code/aes256.c:78: tmp[idx + 2] = (uint8_t)(state[idx + 0] ^ state[idx + 1] ^ xtime(state[idx + 2]) ^ xtime(state[idx + 3]) ^ state[idx + 3]);
	ld	a, -10 (ix)
	inc	a
	inc	a
	ld	e, a
	rla
	sbc	a, a
	ld	d, a
	ld	a, e
	add	a, -12 (ix)
	ld	e, a
	ld	a, d
	adc	a, -11 (ix)
	ld	d, a
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	ld	a, (hl)
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	l, (hl)
	xor	a, l
	ld	-1 (ix), a
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -1 (ix)
	ld	-1 (ix), a
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -1 (ix)
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	l, (hl)
	xor	a, l
	ld	(de), a
	C$aes256.c$79$3_0$45	= .
	.globl	C$aes256.c$79$3_0$45
;/work/source_code/aes256.c:79: tmp[idx + 3] = (uint8_t)(xtime(state[idx + 0]) ^ state[idx + 0] ^ state[idx + 1] ^ state[idx + 2] ^ xtime(state[idx + 3]));
	ld	a, -10 (ix)
	inc	a
	inc	a
	inc	a
	ld	e, a
	rla
	sbc	a, a
	ld	d, a
	ld	a, e
	add	a, -12 (ix)
	ld	e, a
	ld	a, d
	adc	a, -11 (ix)
	ld	d, a
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	l, (hl)
	xor	a, l
	ld	-1 (ix), a
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	a, (hl)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -1 (ix)
	ld	(de), a
	C$aes256.c$74$2_0$44	= .
	.globl	C$aes256.c$74$2_0$44
;/work/source_code/aes256.c:74: for (int i = 0; i < 4; i++) {
	inc	bc
	jp	00103$
00101$:
	C$aes256.c$82$1_0$43	= .
	.globl	C$aes256.c$82$1_0$43
;/work/source_code/aes256.c:82: memcpy(state, tmp, 16);
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	bc, #0x0010
	ldir
	C$aes256.c$83$1_0$43	= .
	.globl	C$aes256.c$83$1_0$43
;/work/source_code/aes256.c:83: }
	ld	sp, ix
	pop	ix
	C$aes256.c$83$1_0$43	= .
	.globl	C$aes256.c$83$1_0$43
	XFaes256$mix_columns$0$0	= .
	.globl	XFaes256$mix_columns$0$0
	ret
	Faes256$add_round_key$0$0	= .
	.globl	Faes256$add_round_key$0$0
	C$aes256.c$85$1_0$48	= .
	.globl	C$aes256.c$85$1_0$48
;/work/source_code/aes256.c:85: static void add_round_key(uint8_t *state, const uint8_t *round_key) {
;	---------------------------------
; Function add_round_key
; ---------------------------------
_add_round_key:
	push	ix
	ld	ix,#0
	add	ix,sp
	dec	sp
	C$aes256.c$86$2_0$48	= .
	.globl	C$aes256.c$86$2_0$48
;/work/source_code/aes256.c:86: for (int i = 0; i < 16; i++) {
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00105$
	C$aes256.c$87$3_0$49	= .
	.globl	C$aes256.c$87$3_0$49
;/work/source_code/aes256.c:87: state[i] ^= round_key[i];
	ld	a, 4 (ix)
	add	a, c
	ld	e, a
	ld	a, 5 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	ld	-1 (ix), a
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, bc
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	(de), a
	C$aes256.c$86$2_0$48	= .
	.globl	C$aes256.c$86$2_0$48
;/work/source_code/aes256.c:86: for (int i = 0; i < 16; i++) {
	inc	bc
	jr	00103$
00105$:
	C$aes256.c$89$2_0$48	= .
	.globl	C$aes256.c$89$2_0$48
;/work/source_code/aes256.c:89: }
	inc	sp
	pop	ix
	C$aes256.c$89$2_0$48	= .
	.globl	C$aes256.c$89$2_0$48
	XFaes256$add_round_key$0$0	= .
	.globl	XFaes256$add_round_key$0$0
	ret
	Faes256$key_expansion$0$0	= .
	.globl	Faes256$key_expansion$0$0
	C$aes256.c$91$2_0$51	= .
	.globl	C$aes256.c$91$2_0$51
;/work/source_code/aes256.c:91: static void key_expansion(const uint8_t *key, AES256_CTX *ctx) {
;	---------------------------------
; Function key_expansion
; ---------------------------------
_key_expansion:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-20
	add	hl, sp
	ld	sp, hl
	C$aes256.c$93$1_0$51	= .
	.globl	C$aes256.c$93$1_0$51
;/work/source_code/aes256.c:93: uint32_t *w = (uint32_t *)ctx->round_keys;
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	c, e
	ld	b, d
	ld	-12 (ix), c
	ld	-11 (ix), b
	C$aes256.c$97$1_0$51	= .
	.globl	C$aes256.c$97$1_0$51
;/work/source_code/aes256.c:97: memcpy(ctx->round_keys, key, 32);
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	ld	bc, #0x0020
	ldir
	C$aes256.c$100$4_0$54	= .
	.globl	C$aes256.c$100$4_0$54
;/work/source_code/aes256.c:100: for (i = 8; i < 4 * (AES_ROUNDS + 1); i++) {
	ld	bc, #0x0008
00107$:
	C$aes256.c$101$3_0$53	= .
	.globl	C$aes256.c$101$3_0$53
;/work/source_code/aes256.c:101: memcpy(temp, &w[i - 1], 4);
	ld	hl, #0
	add	hl, sp
	ld	-10 (ix), l
	ld	-9 (ix), h
	ex	de,hl
	ld	l, c
	ld	h, b
	dec	hl
	add	hl, hl
	add	hl, hl
	ld	a, -12 (ix)
	add	a, l
	ld	l, a
	ld	a, -11 (ix)
	adc	a, h
	ld	h, a
	push	bc
	ld	bc, #0x0004
	ldir
	pop	bc
	C$aes256.c$103$2_0$51	= .
	.globl	C$aes256.c$103$2_0$51
;/work/source_code/aes256.c:103: if (i % 8 == 0) {
	push	bc
	ld	hl, #0x0008
	push	hl
	push	bc
	call	__modsint
	pop	af
	pop	af
	ex	de,hl
	pop	bc
	ld	a, d
	or	a, e
	jp	NZ, 00104$
	C$aes256.c$105$4_0$54	= .
	.globl	C$aes256.c$105$4_0$54
;/work/source_code/aes256.c:105: uint8_t t = temp[0];
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	a, (hl)
	ld	-8 (ix), a
	C$aes256.c$106$4_0$54	= .
	.globl	C$aes256.c$106$4_0$54
;/work/source_code/aes256.c:106: temp[0] = temp[1];
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	inc	de
	ld	a, (de)
	ld	-7 (ix), a
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	a, -7 (ix)
	ld	(hl), a
	C$aes256.c$107$4_0$54	= .
	.globl	C$aes256.c$107$4_0$54
;/work/source_code/aes256.c:107: temp[1] = temp[2];
	ld	a, -10 (ix)
	add	a, #0x02
	ld	-6 (ix), a
	ld	a, -9 (ix)
	adc	a, #0x00
	ld	-5 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	a, (hl)
	ld	-4 (ix), a
	ld	(de),a
	C$aes256.c$108$4_0$54	= .
	.globl	C$aes256.c$108$4_0$54
;/work/source_code/aes256.c:108: temp[2] = temp[3];
	ld	a, -10 (ix)
	add	a, #0x03
	ld	-3 (ix), a
	ld	a, -9 (ix)
	adc	a, #0x00
	ld	-2 (ix), a
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	a, (hl)
	ld	-1 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	a, -1 (ix)
	ld	(hl), a
	C$aes256.c$109$4_0$54	= .
	.globl	C$aes256.c$109$4_0$54
;/work/source_code/aes256.c:109: temp[3] = t;
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	a, -8 (ix)
	ld	(hl), a
	C$aes256.c$112$4_0$54	= .
	.globl	C$aes256.c$112$4_0$54
;/work/source_code/aes256.c:112: temp[0] = sbox[temp[0]];
	ld	a, #<(_sbox)
	add	a, -7 (ix)
	ld	l, a
	ld	a, #>(_sbox)
	adc	a, #0x00
	ld	h, a
	ld	a, (hl)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	(hl), a
	C$aes256.c$113$4_0$54	= .
	.globl	C$aes256.c$113$4_0$54
;/work/source_code/aes256.c:113: temp[1] = sbox[temp[1]];
	ld	a, #<(_sbox)
	add	a, -4 (ix)
	ld	l, a
	ld	a, #>(_sbox)
	adc	a, #0x00
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	C$aes256.c$114$4_0$54	= .
	.globl	C$aes256.c$114$4_0$54
;/work/source_code/aes256.c:114: temp[2] = sbox[temp[2]];
	ld	a, #<(_sbox)
	add	a, -1 (ix)
	ld	e, a
	ld	a, #>(_sbox)
	adc	a, #0x00
	ld	d, a
	ld	a, (de)
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	(hl), a
	C$aes256.c$115$4_0$54	= .
	.globl	C$aes256.c$115$4_0$54
;/work/source_code/aes256.c:115: temp[3] = sbox[temp[3]];
	ld	a, #<(_sbox)
	add	a, -8 (ix)
	ld	e, a
	ld	a, #>(_sbox)
	adc	a, #0x00
	ld	d, a
	ld	a, (de)
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	(hl), a
	C$aes256.c$117$4_0$54	= .
	.globl	C$aes256.c$117$4_0$54
;/work/source_code/aes256.c:117: temp[0] ^= rcon[i / 8];
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	a, (hl)
	ld	-1 (ix), a
	ld	l, c
	ld	h, b
	bit	7, b
	jr	Z,00111$
	ld	hl, #0x0007
	add	hl, bc
00111$:
	sra	h
	rr	l
	sra	h
	rr	l
	sra	h
	rr	l
	push	de
	ld	de, #_rcon
	add	hl, de
	pop	de
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	(de), a
	jr	00105$
00104$:
	C$aes256.c$118$3_0$53	= .
	.globl	C$aes256.c$118$3_0$53
;/work/source_code/aes256.c:118: } else if (i % 8 == 4) {
	ld	a, e
	sub	a, #0x04
	or	a, d
	jr	NZ,00105$
	C$aes256.c$120$4_0$55	= .
	.globl	C$aes256.c$120$4_0$55
;/work/source_code/aes256.c:120: temp[0] = sbox[temp[0]];
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	e, (hl)
	ld	hl, #_sbox
	ld	d, #0x00
	add	hl, de
	ld	a, (hl)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	(hl), a
	C$aes256.c$121$4_0$55	= .
	.globl	C$aes256.c$121$4_0$55
;/work/source_code/aes256.c:121: temp[1] = sbox[temp[1]];
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	inc	de
	ld	a, (de)
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	C$aes256.c$122$4_0$55	= .
	.globl	C$aes256.c$122$4_0$55
;/work/source_code/aes256.c:122: temp[2] = sbox[temp[2]];
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	inc	de
	inc	de
	ld	a, (de)
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	C$aes256.c$123$4_0$55	= .
	.globl	C$aes256.c$123$4_0$55
;/work/source_code/aes256.c:123: temp[3] = sbox[temp[3]];
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	inc	de
	inc	de
	inc	de
	ld	a, (de)
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
00105$:
	C$aes256.c$126$3_1$56	= .
	.globl	C$aes256.c$126$3_1$56
;/work/source_code/aes256.c:126: uint32_t prev = w[i - 8];
	ld	a, c
	add	a, #0xf8
	ld	l, a
	ld	a, b
	adc	a, #0xff
	ld	h, a
	add	hl, hl
	add	hl, hl
	ld	e, -12 (ix)
	ld	d, -11 (ix)
	add	hl, de
	push	bc
	ex	de,hl
	ld	hl, #0x0012
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	bc
	C$aes256.c$128$3_1$56	= .
	.globl	C$aes256.c$128$3_1$56
;/work/source_code/aes256.c:128: memcpy(&new_word, temp, 4);
	ld	hl, #4
	add	hl, sp
	ex	de, hl
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	push	bc
	ld	bc, #0x0004
	ldir
	pop	bc
	C$aes256.c$129$3_1$56	= .
	.globl	C$aes256.c$129$3_1$56
;/work/source_code/aes256.c:129: w[i] = prev ^ new_word;
	ld	l, c
	ld	h, b
	add	hl, hl
	add	hl, hl
	ld	e, -12 (ix)
	ld	d, -11 (ix)
	add	hl, de
	ld	a, -4 (ix)
	xor	a, -16 (ix)
	ld	-8 (ix), a
	ld	a, -3 (ix)
	xor	a, -15 (ix)
	ld	-7 (ix), a
	ld	a, -2 (ix)
	xor	a, -14 (ix)
	ld	-6 (ix), a
	ld	a, -1 (ix)
	xor	a, -13 (ix)
	ld	-5 (ix), a
	push	bc
	ex	de,hl
	ld	hl, #0x000e
	add	hl, sp
	ld	bc, #0x0004
	ldir
	pop	bc
	C$aes256.c$100$2_0$52	= .
	.globl	C$aes256.c$100$2_0$52
;/work/source_code/aes256.c:100: for (i = 8; i < 4 * (AES_ROUNDS + 1); i++) {
	inc	bc
	ld	a, c
	sub	a, #0x3c
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	C, 00107$
	C$aes256.c$131$2_0$51	= .
	.globl	C$aes256.c$131$2_0$51
;/work/source_code/aes256.c:131: }
	ld	sp, ix
	pop	ix
	C$aes256.c$131$2_0$51	= .
	.globl	C$aes256.c$131$2_0$51
	XFaes256$key_expansion$0$0	= .
	.globl	XFaes256$key_expansion$0$0
	ret
	G$aes256_encrypt$0$0	= .
	.globl	G$aes256_encrypt$0$0
	C$aes256.c$133$2_0$58	= .
	.globl	C$aes256.c$133$2_0$58
;/work/source_code/aes256.c:133: void aes256_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *key) {
;	---------------------------------
; Function aes256_encrypt
; ---------------------------------
_aes256_encrypt::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-268
	add	hl, sp
	ld	sp, hl
	C$aes256.c$137$1_0$58	= .
	.globl	C$aes256.c$137$1_0$58
;/work/source_code/aes256.c:137: key_expansion(key, &ctx);
	ld	hl, #0
	add	hl, sp
	ld	-12 (ix), l
	ld	-11 (ix), h
	push	hl
	ld	l, 8 (ix)
	ld	h, 9 (ix)
	push	hl
	call	_key_expansion
	pop	af
	pop	af
	C$aes256.c$138$1_0$58	= .
	.globl	C$aes256.c$138$1_0$58
;/work/source_code/aes256.c:138: memcpy(state, plaintext, 16);
	ld	hl, #240
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	e, c
	ld	d, b
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	bc
	ld	bc, #0x0010
	ldir
	pop	bc
	C$aes256.c$140$1_0$58	= .
	.globl	C$aes256.c$140$1_0$58
;/work/source_code/aes256.c:140: add_round_key(state, ctx.round_keys[0]);
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	e, c
	ld	d, b
	push	bc
	push	hl
	push	de
	call	_add_round_key
	pop	af
	pop	af
	pop	bc
	C$aes256.c$142$3_0$60	= .
	.globl	C$aes256.c$142$3_0$60
;/work/source_code/aes256.c:142: for (int round = 1; round < AES_ROUNDS; round++) {
	ld	-10 (ix), c
	ld	-9 (ix), b
	ld	-8 (ix), c
	ld	-7 (ix), b
	ld	-6 (ix), c
	ld	-5 (ix), b
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	-2 (ix), #0x01
	xor	a, a
	ld	-1 (ix), a
00103$:
	ld	a, -2 (ix)
	sub	a, #0x0e
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$aes256.c$143$3_0$60	= .
	.globl	C$aes256.c$143$3_0$60
;/work/source_code/aes256.c:143: sub_bytes(state);
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	push	bc
	push	de
	call	_sub_bytes
	pop	af
	pop	bc
	C$aes256.c$144$3_0$60	= .
	.globl	C$aes256.c$144$3_0$60
;/work/source_code/aes256.c:144: shift_rows(state);
	ld	e, -8 (ix)
	ld	d, -7 (ix)
	push	bc
	push	de
	call	_shift_rows
	pop	af
	pop	bc
	C$aes256.c$145$3_0$60	= .
	.globl	C$aes256.c$145$3_0$60
;/work/source_code/aes256.c:145: mix_columns(state);
	ld	e, -6 (ix)
	ld	d, -5 (ix)
	push	bc
	push	de
	call	_mix_columns
	pop	af
	pop	bc
	C$aes256.c$146$3_0$60	= .
	.globl	C$aes256.c$146$3_0$60
;/work/source_code/aes256.c:146: add_round_key(state, ctx.round_keys[round]);
	ld	e, -2 (ix)
	ld	d, -1 (ix)
	sla	e
	rl	d
	sla	e
	rl	d
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, e
	add	a, -12 (ix)
	ld	e, a
	ld	a, d
	adc	a, -11 (ix)
	ld	d, a
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	bc
	push	de
	push	hl
	call	_add_round_key
	pop	af
	pop	af
	pop	bc
	C$aes256.c$142$2_0$59	= .
	.globl	C$aes256.c$142$2_0$59
;/work/source_code/aes256.c:142: for (int round = 1; round < AES_ROUNDS; round++) {
	inc	-2 (ix)
	jr	NZ,00103$
	inc	-1 (ix)
	jr	00103$
00101$:
	C$aes256.c$149$1_0$58	= .
	.globl	C$aes256.c$149$1_0$58
;/work/source_code/aes256.c:149: sub_bytes(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_sub_bytes
	pop	af
	pop	bc
	C$aes256.c$150$1_0$58	= .
	.globl	C$aes256.c$150$1_0$58
;/work/source_code/aes256.c:150: shift_rows(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_shift_rows
	pop	af
	pop	bc
	C$aes256.c$151$1_0$58	= .
	.globl	C$aes256.c$151$1_0$58
;/work/source_code/aes256.c:151: add_round_key(state, ctx.round_keys[AES_ROUNDS]);
	ld	a, -12 (ix)
	add	a, #0xe0
	ld	e, a
	ld	a, -11 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	push	de
	push	hl
	call	_add_round_key
	pop	af
	pop	af
	pop	bc
	C$aes256.c$153$1_0$58	= .
	.globl	C$aes256.c$153$1_0$58
;/work/source_code/aes256.c:153: memcpy(ciphertext, state, 16);
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	l, c
	ld	h, b
	ld	bc, #0x0010
	ldir
	C$aes256.c$154$1_0$58	= .
	.globl	C$aes256.c$154$1_0$58
;/work/source_code/aes256.c:154: }
	ld	sp, ix
	pop	ix
	C$aes256.c$154$1_0$58	= .
	.globl	C$aes256.c$154$1_0$58
	XG$aes256_encrypt$0$0	= .
	.globl	XG$aes256_encrypt$0$0
	ret
	G$main$0$0	= .
	.globl	G$main$0$0
	C$aes256.c$156$1_0$61	= .
	.globl	C$aes256.c$156$1_0$61
;/work/source_code/aes256.c:156: int main() {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-68
	add	hl, sp
	ld	sp, hl
	C$aes256.c$157$2_0$61	= .
	.globl	C$aes256.c$157$2_0$61
;/work/source_code/aes256.c:157: uint8_t key[32] = {
	ld	hl, #0
	add	hl, sp
	ex	de, hl
	ld	a, #0x60
	ld	(de), a
	ld	l, e
	ld	h, d
	inc	hl
	ld	(hl), #0x3d
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	ld	(hl), #0xeb
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0x10
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0x15
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0xca
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0x71
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0xbe
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0x2b
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0x73
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0xae
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0xf0
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0x85
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0x7d
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x77
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0x81
	ld	hl, #0x0010
	add	hl, de
	ld	(hl), #0x1f
	ld	hl, #0x0011
	add	hl, de
	ld	(hl), #0x35
	ld	hl, #0x0012
	add	hl, de
	ld	(hl), #0x2c
	ld	hl, #0x0013
	add	hl, de
	ld	(hl), #0x07
	ld	hl, #0x0014
	add	hl, de
	ld	(hl), #0x3b
	ld	hl, #0x0015
	add	hl, de
	ld	(hl), #0x61
	ld	hl, #0x0016
	add	hl, de
	ld	(hl), #0x08
	ld	hl, #0x0017
	add	hl, de
	ld	(hl), #0xd7
	ld	hl, #0x0018
	add	hl, de
	ld	(hl), #0x2d
	ld	hl, #0x0019
	add	hl, de
	ld	(hl), #0x98
	ld	hl, #0x001a
	add	hl, de
	ld	(hl), #0x10
	ld	hl, #0x001b
	add	hl, de
	ld	(hl), #0xa3
	ld	hl, #0x001c
	add	hl, de
	ld	(hl), #0x09
	ld	hl, #0x001d
	add	hl, de
	ld	(hl), #0x14
	ld	hl, #0x001e
	add	hl, de
	ld	(hl), #0xdf
	ld	hl, #0x001f
	add	hl, de
	ld	(hl), #0xf4
	C$aes256.c$164$2_0$61	= .
	.globl	C$aes256.c$164$2_0$61
;/work/source_code/aes256.c:164: uint8_t plaintext[16] = {
	ld	hl, #32
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	a, #0x32
	ld	(bc), a
	ld	l, c
	ld	h, b
	inc	hl
	ld	(hl), #0x43
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	(hl), #0xf6
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xa8
	ld	hl, #0x0004
	add	hl, bc
	ld	(hl), #0x88
	ld	hl, #0x0005
	add	hl, bc
	ld	(hl), #0x5a
	ld	hl, #0x0006
	add	hl, bc
	ld	(hl), #0x30
	ld	hl, #0x0007
	add	hl, bc
	ld	(hl), #0x8d
	ld	hl, #0x0008
	add	hl, bc
	ld	(hl), #0x31
	ld	hl, #0x0009
	add	hl, bc
	ld	(hl), #0x31
	ld	hl, #0x000a
	add	hl, bc
	ld	(hl), #0x98
	ld	hl, #0x000b
	add	hl, bc
	ld	(hl), #0xa2
	ld	hl, #0x000c
	add	hl, bc
	ld	(hl), #0xe0
	ld	hl, #0x000d
	add	hl, bc
	ld	(hl), #0x37
	ld	hl, #0x000e
	add	hl, bc
	ld	(hl), #0x07
	ld	hl, #0x000f
	add	hl, bc
	ld	(hl), #0x34
	C$aes256.c$171$1_0$61	= .
	.globl	C$aes256.c$171$1_0$61
;/work/source_code/aes256.c:171: aes256_encrypt(plaintext, ciphertext, key);
	ld	hl, #48
	add	hl, sp
	ld	-4 (ix), l
	ld	-3 (ix), h
	ld	a, -4 (ix)
	ld	-2 (ix), a
	ld	a, -3 (ix)
	ld	-1 (ix), a
	ld	l, c
	ld	h, b
	push	bc
	push	de
	ld	e, -2 (ix)
	ld	d, -1 (ix)
	push	de
	push	hl
	call	_aes256_encrypt
	ld	hl, #6
	add	hl, sp
	ld	sp, hl
	ld	hl, #___str_1
	push	hl
	call	_puts
	ld	hl, #___str_2
	ex	(sp),hl
	call	_printf
	pop	af
	pop	bc
	C$aes256.c$175$2_0$62	= .
	.globl	C$aes256.c$175$2_0$62
;/work/source_code/aes256.c:175: for (int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
	ld	de, #0x0000
00104$:
	ld	a, e
	sub	a, #0x10
	ld	a, d
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	ld	l, c
	ld	h, b
	add	hl, de
	ld	l, (hl)
	ld	h, #0x00
	push	bc
	push	de
	push	hl
	ld	hl, #___str_3
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	de
	pop	bc
	inc	de
	jr	00104$
00101$:
	C$aes256.c$176$1_0$61	= .
	.globl	C$aes256.c$176$1_0$61
;/work/source_code/aes256.c:176: printf("\n");
	ld	hl, #___str_5
	push	hl
	call	_puts
	C$aes256.c$178$1_0$61	= .
	.globl	C$aes256.c$178$1_0$61
;/work/source_code/aes256.c:178: printf("Ciphertext: ");
	ld	hl, #___str_6
	ex	(sp),hl
	call	_printf
	pop	af
	C$aes256.c$179$2_0$63	= .
	.globl	C$aes256.c$179$2_0$63
;/work/source_code/aes256.c:179: for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
	ld	bc, #0x0000
00107$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00102$
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	add	hl, bc
	ld	e, (hl)
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_3
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
	inc	bc
	jr	00107$
00102$:
	C$aes256.c$180$1_0$61	= .
	.globl	C$aes256.c$180$1_0$61
;/work/source_code/aes256.c:180: printf("\n");
	ld	hl, #___str_5
	push	hl
	call	_puts
	pop	af
	C$aes256.c$182$1_0$61	= .
	.globl	C$aes256.c$182$1_0$61
;/work/source_code/aes256.c:182: return 0;
	ld	hl, #0x0000
	C$aes256.c$183$1_0$61	= .
	.globl	C$aes256.c$183$1_0$61
;/work/source_code/aes256.c:183: }
	ld	sp, ix
	pop	ix
	C$aes256.c$183$1_0$61	= .
	.globl	C$aes256.c$183$1_0$61
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Faes256$__str_1$0_0$0 == .
___str_1:
	.ascii "AES-256 Encryption"
	.db 0x00
Faes256$__str_2$0_0$0 == .
___str_2:
	.ascii "Plaintext:  "
	.db 0x00
Faes256$__str_3$0_0$0 == .
___str_3:
	.ascii "%02x "
	.db 0x00
Faes256$__str_5$0_0$0 == .
___str_5:
	.db 0x00
Faes256$__str_6$0_0$0 == .
___str_6:
	.ascii "Ciphertext: "
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
