;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module aes192
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _aes192_encrypt
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
	Faes192$xtime$0$0	= .
	.globl	Faes192$xtime$0$0
	C$aes192.c$36$0_0$12	= .
	.globl	C$aes192.c$36$0_0$12
;/work/source_code/aes192.c:36: static uint8_t xtime(uint8_t x) {
;	---------------------------------
; Function xtime
; ---------------------------------
_xtime:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes192.c$37$1_0$12	= .
	.globl	C$aes192.c$37$1_0$12
;/work/source_code/aes192.c:37: return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
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
00101$:
	C$aes192.c$38$1_0$12	= .
	.globl	C$aes192.c$38$1_0$12
;/work/source_code/aes192.c:38: }
	pop	ix
	C$aes192.c$38$1_0$12	= .
	.globl	C$aes192.c$38$1_0$12
	XFaes192$xtime$0$0	= .
	.globl	XFaes192$xtime$0$0
	ret
Faes192$sbox$0_0$0 == .
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
Faes192$rcon$0_0$0 == .
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
	Faes192$sub_bytes$0$0	= .
	.globl	Faes192$sub_bytes$0$0
	C$aes192.c$40$1_0$15	= .
	.globl	C$aes192.c$40$1_0$15
;/work/source_code/aes192.c:40: static void sub_bytes(uint8_t state[4][4]) {
;	---------------------------------
; Function sub_bytes
; ---------------------------------
_sub_bytes:
	push	ix
	ld	ix,#0
	add	ix,sp
	push	af
	push	af
	C$aes192.c$41$5_0$18	= .
	.globl	C$aes192.c$41$5_0$18
;/work/source_code/aes192.c:41: for (int i = 0; i < 4; i++) {
	ld	bc, #0x0000
00107$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00109$
	C$aes192.c$42$5_0$18	= .
	.globl	C$aes192.c$42$5_0$18
;/work/source_code/aes192.c:42: for (int j = 0; j < 4; j++) {
	ld	e, c
	ld	d, b
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, e
	add	a, 4 (ix)
	ld	-4 (ix), a
	ld	a, d
	adc	a, 5 (ix)
	ld	-3 (ix), a
	ld	de, #0x0000
00104$:
	ld	a, e
	sub	a, #0x04
	ld	a, d
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00108$
	C$aes192.c$43$5_0$18	= .
	.globl	C$aes192.c$43$5_0$18
;/work/source_code/aes192.c:43: state[i][j] = sbox[state[i][j]];
	ld	a, -4 (ix)
	add	a, e
	ld	-2 (ix), a
	ld	a, -3 (ix)
	adc	a, d
	ld	-1 (ix), a
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	a, (hl)
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$aes192.c$42$4_0$17	= .
	.globl	C$aes192.c$42$4_0$17
;/work/source_code/aes192.c:42: for (int j = 0; j < 4; j++) {
	inc	de
	jp	00104$
00108$:
	C$aes192.c$41$2_0$15	= .
	.globl	C$aes192.c$41$2_0$15
;/work/source_code/aes192.c:41: for (int i = 0; i < 4; i++) {
	inc	bc
	jp	00107$
00109$:
	C$aes192.c$46$2_0$15	= .
	.globl	C$aes192.c$46$2_0$15
;/work/source_code/aes192.c:46: }
	ld	sp, ix
	pop	ix
	C$aes192.c$46$2_0$15	= .
	.globl	C$aes192.c$46$2_0$15
	XFaes192$sub_bytes$0$0	= .
	.globl	XFaes192$sub_bytes$0$0
	ret
	Faes192$shift_rows$0$0	= .
	.globl	Faes192$shift_rows$0$0
	C$aes192.c$48$2_0$20	= .
	.globl	C$aes192.c$48$2_0$20
;/work/source_code/aes192.c:48: static void shift_rows(uint8_t state[4][4]) {
;	---------------------------------
; Function shift_rows
; ---------------------------------
_shift_rows:
	push	ix
	ld	ix,#0
	add	ix,sp
	push	af
	dec	sp
	C$aes192.c$52$1_0$20	= .
	.globl	C$aes192.c$52$1_0$20
;/work/source_code/aes192.c:52: temp = state[1][0];
	ld	a, 4 (ix)
	add	a, #0x04
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, (bc)
	ld	-3 (ix), a
	C$aes192.c$53$1_0$20	= .
	.globl	C$aes192.c$53$1_0$20
;/work/source_code/aes192.c:53: state[1][0] = state[1][1];
	ld	l, c
	ld	h, b
	inc	hl
	ld	a, (hl)
	ld	(bc), a
	C$aes192.c$54$1_0$20	= .
	.globl	C$aes192.c$54$1_0$20
;/work/source_code/aes192.c:54: state[1][1] = state[1][2];
	ld	a, 4 (ix)
	add	a, #0x04
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	hl, #0x0001
	add	hl, bc
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	e, c
	ld	d, b
	inc	de
	inc	de
	ld	a, (de)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$aes192.c$55$1_0$20	= .
	.globl	C$aes192.c$55$1_0$20
;/work/source_code/aes192.c:55: state[1][2] = state[1][3];
	inc	bc
	inc	bc
	inc	bc
	ld	a, (bc)
	ld	(de), a
	C$aes192.c$56$1_0$20	= .
	.globl	C$aes192.c$56$1_0$20
;/work/source_code/aes192.c:56: state[1][3] = temp;
	ld	a, -3 (ix)
	ld	(bc), a
	C$aes192.c$59$1_0$20	= .
	.globl	C$aes192.c$59$1_0$20
;/work/source_code/aes192.c:59: temp = state[2][0];
	ld	a, 4 (ix)
	add	a, #0x08
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, (bc)
	ld	e, a
	C$aes192.c$60$1_0$20	= .
	.globl	C$aes192.c$60$1_0$20
;/work/source_code/aes192.c:60: state[2][0] = state[2][2];
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(bc), a
	C$aes192.c$61$1_0$20	= .
	.globl	C$aes192.c$61$1_0$20
;/work/source_code/aes192.c:61: state[2][2] = temp;
	ld	a, 4 (ix)
	add	a, #0x08
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	(hl), e
	C$aes192.c$62$1_0$20	= .
	.globl	C$aes192.c$62$1_0$20
;/work/source_code/aes192.c:62: temp = state[2][1];
	ld	e, c
	ld	d, b
	inc	de
	ld	a, (de)
	ld	-1 (ix), a
	C$aes192.c$63$1_0$20	= .
	.globl	C$aes192.c$63$1_0$20
;/work/source_code/aes192.c:63: state[2][1] = state[2][3];
	inc	bc
	inc	bc
	inc	bc
	ld	a, (bc)
	ld	(de), a
	C$aes192.c$64$1_0$20	= .
	.globl	C$aes192.c$64$1_0$20
;/work/source_code/aes192.c:64: state[2][3] = temp;
	ld	a, -1 (ix)
	ld	(bc), a
	C$aes192.c$67$1_0$20	= .
	.globl	C$aes192.c$67$1_0$20
;/work/source_code/aes192.c:67: temp = state[3][3];
	ld	a, 4 (ix)
	add	a, #0x0c
	ld	c, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	b, a
	ld	e, c
	ld	d, b
	inc	de
	inc	de
	inc	de
	ld	a, (de)
	ld	-3 (ix), a
	C$aes192.c$68$1_0$20	= .
	.globl	C$aes192.c$68$1_0$20
;/work/source_code/aes192.c:68: state[3][3] = state[3][2];
	ld	hl, #0x0002
	add	hl, bc
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$69$1_0$20	= .
	.globl	C$aes192.c$69$1_0$20
;/work/source_code/aes192.c:69: state[3][2] = state[3][1];
	ld	e, c
	ld	d, b
	inc	de
	ld	a, (de)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$aes192.c$70$1_0$20	= .
	.globl	C$aes192.c$70$1_0$20
;/work/source_code/aes192.c:70: state[3][1] = state[3][0];
	ld	a, (bc)
	ld	(de), a
	C$aes192.c$71$1_0$20	= .
	.globl	C$aes192.c$71$1_0$20
;/work/source_code/aes192.c:71: state[3][0] = temp;
	ld	a, -3 (ix)
	ld	(bc), a
00101$:
	C$aes192.c$72$1_0$20	= .
	.globl	C$aes192.c$72$1_0$20
;/work/source_code/aes192.c:72: }
	ld	sp, ix
	pop	ix
	C$aes192.c$72$1_0$20	= .
	.globl	C$aes192.c$72$1_0$20
	XFaes192$shift_rows$0$0	= .
	.globl	XFaes192$shift_rows$0$0
	ret
	Faes192$mix_columns$0$0	= .
	.globl	Faes192$mix_columns$0$0
	C$aes192.c$74$1_0$23	= .
	.globl	C$aes192.c$74$1_0$23
;/work/source_code/aes192.c:74: static void mix_columns(uint8_t state[4][4]) {
;	---------------------------------
; Function mix_columns
; ---------------------------------
_mix_columns:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-27
	add	hl, sp
	ld	sp, hl
	C$aes192.c$77$3_0$24	= .
	.globl	C$aes192.c$77$3_0$24
;/work/source_code/aes192.c:77: for (int i = 0; i < 4; i++) {
	ld	c, 4 (ix)
	ld	b, 5 (ix)
	ld	hl, #0x0004
	add	hl, bc
	ld	-21 (ix), l
	ld	-20 (ix), h
	ld	hl, #0x0008
	add	hl, bc
	ld	-19 (ix), l
	ld	-18 (ix), h
	ld	hl, #0x000c
	add	hl, bc
	ld	-17 (ix), l
	ld	-16 (ix), h
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00103$:
	ld	a, -2 (ix)
	sub	a, #0x04
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00105$
	C$aes192.c$78$3_0$24	= .
	.globl	C$aes192.c$78$3_0$24
;/work/source_code/aes192.c:78: tmp[0] = state[0][i];
	ld	hl, #2
	add	hl, sp
	ex	de, hl
	ld	a, c
	add	a, -2 (ix)
	ld	-27 (ix), a
	ld	a, b
	adc	a, -1 (ix)
	ld	-26 (ix), a
	pop	hl
	push	hl
	ld	a, (hl)
	ld	-3 (ix), a
	ld	a, -3 (ix)
	ld	(de), a
	C$aes192.c$79$3_0$24	= .
	.globl	C$aes192.c$79$3_0$24
;/work/source_code/aes192.c:79: tmp[1] = state[1][i];
	ld	hl, #0x0001
	add	hl, de
	ld	-15 (ix), l
	ld	-14 (ix), h
	ld	a, -21 (ix)
	add	a, -2 (ix)
	ld	-13 (ix), a
	ld	a, -20 (ix)
	adc	a, -1 (ix)
	ld	-12 (ix), a
	ld	l, -13 (ix)
	ld	h, -12 (ix)
	ld	a, (hl)
	ld	l, -15 (ix)
	ld	h, -14 (ix)
	ld	(hl), a
	C$aes192.c$80$3_0$24	= .
	.globl	C$aes192.c$80$3_0$24
;/work/source_code/aes192.c:80: tmp[2] = state[2][i];
	ld	hl, #0x0002
	add	hl, de
	ld	-11 (ix), l
	ld	-10 (ix), h
	ld	a, -19 (ix)
	add	a, -2 (ix)
	ld	-9 (ix), a
	ld	a, -18 (ix)
	adc	a, -1 (ix)
	ld	-8 (ix), a
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	ld	a, (hl)
	ld	l, -11 (ix)
	ld	h, -10 (ix)
	ld	(hl), a
	C$aes192.c$81$3_0$24	= .
	.globl	C$aes192.c$81$3_0$24
;/work/source_code/aes192.c:81: tmp[3] = state[3][i];
	ld	hl, #0x0003
	add	hl, de
	ld	-7 (ix), l
	ld	-6 (ix), h
	ld	a, -17 (ix)
	add	a, -2 (ix)
	ld	-5 (ix), a
	ld	a, -16 (ix)
	adc	a, -1 (ix)
	ld	-4 (ix), a
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	a, (hl)
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	(hl), a
	C$aes192.c$83$3_0$24	= .
	.globl	C$aes192.c$83$3_0$24
;/work/source_code/aes192.c:83: state[0][i] = (uint8_t)(xtime(tmp[0]) ^ xtime(tmp[1]) ^ tmp[1] ^ tmp[2] ^ tmp[3]);
	push	bc
	push	de
	ld	a, -3 (ix)
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	-3 (ix), l
	pop	de
	pop	bc
	ld	l, -15 (ix)
	ld	h, -14 (ix)
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
	ld	l, -15 (ix)
	ld	h, -14 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -11 (ix)
	ld	h, -10 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	l, (hl)
	xor	a, l
	pop	hl
	push	hl
	ld	(hl), a
	C$aes192.c$84$3_0$24	= .
	.globl	C$aes192.c$84$3_0$24
;/work/source_code/aes192.c:84: state[1][i] = (uint8_t)(tmp[0] ^ xtime(tmp[1]) ^ xtime(tmp[2]) ^ tmp[2] ^ tmp[3]);
	ld	a, (de)
	ld	-3 (ix), a
	ld	l, -15 (ix)
	ld	h, -14 (ix)
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
	ld	-3 (ix), a
	ld	l, -11 (ix)
	ld	h, -10 (ix)
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
	ld	l, -11 (ix)
	ld	h, -10 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -13 (ix)
	ld	h, -12 (ix)
	ld	(hl), a
	C$aes192.c$85$3_0$24	= .
	.globl	C$aes192.c$85$3_0$24
;/work/source_code/aes192.c:85: state[2][i] = (uint8_t)(tmp[0] ^ tmp[1] ^ xtime(tmp[2]) ^ xtime(tmp[3]) ^ tmp[3]);
	ld	a, (de)
	ld	l, -15 (ix)
	ld	h, -14 (ix)
	ld	l, (hl)
	xor	a, l
	ld	-3 (ix), a
	ld	l, -11 (ix)
	ld	h, -10 (ix)
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
	ld	-3 (ix), a
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
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	ld	(hl), a
	C$aes192.c$86$3_0$24	= .
	.globl	C$aes192.c$86$3_0$24
;/work/source_code/aes192.c:86: state[3][i] = (uint8_t)(xtime(tmp[0]) ^ tmp[0] ^ tmp[1] ^ tmp[2] ^ xtime(tmp[3]));
	ld	a, (de)
	push	bc
	push	de
	push	af
	inc	sp
	call	_xtime
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	push	af
	ld	a, (de)
	ld	e, a
	pop	af
	xor	a, e
	ld	l, -15 (ix)
	ld	h, -14 (ix)
	ld	e, (hl)
	xor	a, e
	ld	l, -11 (ix)
	ld	h, -10 (ix)
	ld	e, (hl)
	xor	a, e
	ld	e, a
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
	xor	a, e
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	(hl), a
	C$aes192.c$77$2_0$23	= .
	.globl	C$aes192.c$77$2_0$23
;/work/source_code/aes192.c:77: for (int i = 0; i < 4; i++) {
	inc	-2 (ix)
	jp	NZ, 00118$
	inc	-1 (ix)
00118$:
	jp	00103$
00105$:
	C$aes192.c$88$2_0$23	= .
	.globl	C$aes192.c$88$2_0$23
;/work/source_code/aes192.c:88: }
	ld	sp, ix
	pop	ix
	C$aes192.c$88$2_0$23	= .
	.globl	C$aes192.c$88$2_0$23
	XFaes192$mix_columns$0$0	= .
	.globl	XFaes192$mix_columns$0$0
	ret
	Faes192$add_round_key$0$0	= .
	.globl	Faes192$add_round_key$0$0
	C$aes192.c$90$2_0$27	= .
	.globl	C$aes192.c$90$2_0$27
;/work/source_code/aes192.c:90: static void add_round_key(uint8_t state[4][4], uint8_t round_key[4][4]) {
;	---------------------------------
; Function add_round_key
; ---------------------------------
_add_round_key:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-6
	add	hl, sp
	ld	sp, hl
	C$aes192.c$91$2_0$27	= .
	.globl	C$aes192.c$91$2_0$27
;/work/source_code/aes192.c:91: for (int i = 0; i < 4; i++) {
	ld	bc, #0x0000
00107$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00109$
	C$aes192.c$92$5_0$30	= .
	.globl	C$aes192.c$92$5_0$30
;/work/source_code/aes192.c:92: for (int j = 0; j < 4; j++) {
	ld	e, c
	ld	d, b
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, 4 (ix)
	add	a, e
	ld	-6 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-5 (ix), a
	ld	a, 6 (ix)
	add	a, e
	ld	-4 (ix), a
	ld	a, 7 (ix)
	adc	a, d
	ld	-3 (ix), a
	ld	de, #0x0000
00104$:
	ld	a, e
	sub	a, #0x04
	ld	a, d
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00108$
	C$aes192.c$93$5_0$30	= .
	.globl	C$aes192.c$93$5_0$30
;/work/source_code/aes192.c:93: state[i][j] ^= round_key[i][j];
	ld	a, -6 (ix)
	add	a, e
	ld	-2 (ix), a
	ld	a, -5 (ix)
	adc	a, d
	ld	-1 (ix), a
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	l, (hl)
	xor	a, l
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$aes192.c$92$4_0$29	= .
	.globl	C$aes192.c$92$4_0$29
;/work/source_code/aes192.c:92: for (int j = 0; j < 4; j++) {
	inc	de
	jp	00104$
00108$:
	C$aes192.c$91$2_0$27	= .
	.globl	C$aes192.c$91$2_0$27
;/work/source_code/aes192.c:91: for (int i = 0; i < 4; i++) {
	inc	bc
	jp	00107$
00109$:
	C$aes192.c$96$2_0$27	= .
	.globl	C$aes192.c$96$2_0$27
;/work/source_code/aes192.c:96: }
	ld	sp, ix
	pop	ix
	C$aes192.c$96$2_0$27	= .
	.globl	C$aes192.c$96$2_0$27
	XFaes192$add_round_key$0$0	= .
	.globl	XFaes192$add_round_key$0$0
	ret
	Faes192$key_expansion_192$0$0	= .
	.globl	Faes192$key_expansion_192$0$0
	C$aes192.c$98$2_0$32	= .
	.globl	C$aes192.c$98$2_0$32
;/work/source_code/aes192.c:98: static void key_expansion_192(const uint8_t *key, AES192_CTX *ctx) {
;	---------------------------------
; Function key_expansion_192
; ---------------------------------
_key_expansion_192:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-30
	add	hl, sp
	ld	sp, hl
	C$aes192.c$105$3_0$34	= .
	.globl	C$aes192.c$105$3_0$34
;/work/source_code/aes192.c:105: for (i = 0; i < key_words; i++) {
	ld	a, 6 (ix)
	ld	-2 (ix), a
	ld	a, 7 (ix)
	ld	-1 (ix), a
	ld	a, -2 (ix)
	ld	-19 (ix), a
	ld	a, -1 (ix)
	ld	-18 (ix), a
	ld	a, -2 (ix)
	ld	-17 (ix), a
	ld	a, -1 (ix)
	ld	-16 (ix), a
	ld	a, -2 (ix)
	ld	-15 (ix), a
	ld	a, -1 (ix)
	ld	-14 (ix), a
	ld	a, -2 (ix)
	ld	-13 (ix), a
	ld	a, -1 (ix)
	ld	-12 (ix), a
	xor	a, a
	ld	-4 (ix), a
	ld	-3 (ix), a
00109$:
	ld	a, -4 (ix)
	sub	a, #0x06
	ld	a, -3 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00101$
	C$aes192.c$106$3_0$34	= .
	.globl	C$aes192.c$106$3_0$34
;/work/source_code/aes192.c:106: ctx->round_keys[i / 4][0][i % 4] = key[4 * i];
	ld	a, -4 (ix)
	ld	-6 (ix), a
	ld	a, -3 (ix)
	ld	-5 (ix), a
	ld	a, -3 (ix)
	rlca
	ld	a, #0x00
	rla
	ld	-11 (ix), a
	ld	a, -4 (ix)
	add	a, #0x03
	ld	-10 (ix), a
	ld	a, -3 (ix)
	adc	a, #0x00
	ld	-9 (ix), a
	ld	a, -11 (ix)
	or	a, a
	jp	Z, 00122$
	ld	a, -10 (ix)
	ld	-6 (ix), a
	ld	a, -9 (ix)
	ld	-5 (ix), a
00122$:
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	sra	h
	rr	l
	sra	h
	rr	l
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	e, -19 (ix)
	ld	d, -18 (ix)
	add	hl, de
	push	hl
	ld	bc, #0x0004
	push	bc
	ld	c, -4 (ix)
	ld	b, -3 (ix)
	push	bc
	call	__modsint
	pop	af
	pop	af
	ld	-8 (ix), l
	ld	-7 (ix), h
	pop	hl
	ld	a, l
	add	a, -8 (ix)
	ld	e, a
	ld	a, h
	adc	a, -7 (ix)
	ld	d, a
	ld	c, -4 (ix)
	ld	b, -3 (ix)
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, bc
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$107$3_0$34	= .
	.globl	C$aes192.c$107$3_0$34
;/work/source_code/aes192.c:107: ctx->round_keys[i / 4][1][i % 4] = key[4 * i + 1];
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, -11 (ix)
	or	a, a
	jp	Z, 00123$
	ld	l, -10 (ix)
	ld	h, -9 (ix)
00123$:
	sra	h
	rr	l
	sra	h
	rr	l
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	e, -17 (ix)
	ld	d, -16 (ix)
	add	hl, de
	ld	de, #0x0004
	add	hl, de
	ld	a, l
	add	a, -8 (ix)
	ld	-6 (ix), a
	ld	a, h
	adc	a, -7 (ix)
	ld	-5 (ix), a
	ld	e, c
	ld	d, b
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	(hl), a
	C$aes192.c$108$3_0$34	= .
	.globl	C$aes192.c$108$3_0$34
;/work/source_code/aes192.c:108: ctx->round_keys[i / 4][2][i % 4] = key[4 * i + 2];
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, -11 (ix)
	or	a, a
	jp	Z, 00124$
	ld	l, -10 (ix)
	ld	h, -9 (ix)
00124$:
	sra	h
	rr	l
	sra	h
	rr	l
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	e, -15 (ix)
	ld	d, -14 (ix)
	add	hl, de
	ld	de, #0x0008
	add	hl, de
	ld	a, l
	add	a, -8 (ix)
	ld	-6 (ix), a
	ld	a, h
	adc	a, -7 (ix)
	ld	-5 (ix), a
	ld	e, c
	ld	d, b
	inc	de
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	(hl), a
	C$aes192.c$109$3_0$34	= .
	.globl	C$aes192.c$109$3_0$34
;/work/source_code/aes192.c:109: ctx->round_keys[i / 4][3][i % 4] = key[4 * i + 3];
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, -11 (ix)
	or	a, a
	jp	Z, 00125$
	ld	l, -10 (ix)
	ld	h, -9 (ix)
00125$:
	sra	h
	rr	l
	sra	h
	rr	l
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	e, -13 (ix)
	ld	d, -12 (ix)
	add	hl, de
	ld	de, #0x000c
	add	hl, de
	ld	a, l
	add	a, -8 (ix)
	ld	e, a
	ld	a, h
	adc	a, -7 (ix)
	ld	d, a
	inc	bc
	inc	bc
	inc	bc
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, bc
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$105$2_0$33	= .
	.globl	C$aes192.c$105$2_0$33
;/work/source_code/aes192.c:105: for (i = 0; i < key_words; i++) {
	inc	-4 (ix)
	jp	NZ, 00226$
	inc	-3 (ix)
00226$:
	jp	00109$
00101$:
	C$aes192.c$113$5_0$38	= .
	.globl	C$aes192.c$113$5_0$38
;/work/source_code/aes192.c:113: for (i = key_words; i < 4 * (num_rounds + 1); i++) {
	ld	a, -2 (ix)
	ld	-24 (ix), a
	ld	a, -1 (ix)
	ld	-23 (ix), a
	ld	a, -2 (ix)
	ld	-22 (ix), a
	ld	a, -1 (ix)
	ld	-21 (ix), a
	ld	a, -2 (ix)
	ld	-20 (ix), a
	ld	a, -1 (ix)
	ld	-19 (ix), a
	ld	-4 (ix), #0x06
	xor	a, a
	ld	-3 (ix), a
00118$:
	ld	a, -4 (ix)
	sub	a, #0x34
	ld	a, -3 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00120$
	C$aes192.c$114$3_0$36	= .
	.globl	C$aes192.c$114$3_0$36
;/work/source_code/aes192.c:114: int prev_word = i - 1;
	ld	a, -4 (ix)
	add	a, #0xff
	ld	-30 (ix), a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	-29 (ix), a
	C$aes192.c$115$3_0$36	= .
	.globl	C$aes192.c$115$3_0$36
;/work/source_code/aes192.c:115: int prev_key_word = i - key_words;
	ld	a, -4 (ix)
	add	a, #0xfa
	ld	-18 (ix), a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	-17 (ix), a
	C$aes192.c$117$5_0$38	= .
	.globl	C$aes192.c$117$5_0$38
;/work/source_code/aes192.c:117: for (j = 0; j < 4; j++) {
	ld	a, -30 (ix)
	add	a, #0x03
	ld	-13 (ix), a
	ld	a, -29 (ix)
	adc	a, #0x00
	ld	-12 (ix), a
	ld	hl, #0x0004
	push	hl
	pop	bc
	pop	hl
	push	hl
	push	bc
	push	hl
	call	__modsint
	pop	af
	pop	af
	ld	-11 (ix), l
	ld	-10 (ix), h
	ld	hl, #2
	add	hl, sp
	ld	-16 (ix), l
	ld	-15 (ix), h
	ld	a, -29 (ix)
	rlca
	ld	a, #0x00
	rla
	ld	-9 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00111$:
	C$aes192.c$118$5_0$38	= .
	.globl	C$aes192.c$118$5_0$38
;/work/source_code/aes192.c:118: temp[j] = ctx->round_keys[prev_word / 4][j][prev_word % 4];
	ld	a, -16 (ix)
	add	a, -2 (ix)
	ld	-8 (ix), a
	ld	a, -15 (ix)
	adc	a, -1 (ix)
	ld	-7 (ix), a
	ld	a, -30 (ix)
	ld	-6 (ix), a
	ld	a, -29 (ix)
	ld	-5 (ix), a
	ld	a, -9 (ix)
	or	a, a
	jp	Z, 00126$
	ld	a, -13 (ix)
	ld	-6 (ix), a
	ld	a, -12 (ix)
	ld	-5 (ix), a
00126$:
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	sra	h
	rr	l
	sra	h
	rr	l
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	a, -24 (ix)
	add	a, l
	ld	c, a
	ld	a, -23 (ix)
	adc	a, h
	ld	b, a
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	add	hl, hl
	add	hl, hl
	add	hl, bc
	ld	e, -11 (ix)
	ld	d, -10 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), a
	C$aes192.c$117$4_0$37	= .
	.globl	C$aes192.c$117$4_0$37
;/work/source_code/aes192.c:117: for (j = 0; j < 4; j++) {
	inc	-2 (ix)
	jp	NZ, 00227$
	inc	-1 (ix)
00227$:
	ld	a, -2 (ix)
	sub	a, #0x04
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	C, 00111$
	C$aes192.c$121$2_0$32	= .
	.globl	C$aes192.c$121$2_0$32
;/work/source_code/aes192.c:121: if (i % key_words == 0) {
	ld	hl, #0x0006
	push	hl
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	hl
	call	__modsint
	pop	af
	pop	af
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -1 (ix)
	or	a, -2 (ix)
	jp	NZ, 00144$
	C$aes192.c$123$4_0$39	= .
	.globl	C$aes192.c$123$4_0$39
;/work/source_code/aes192.c:123: uint8_t t = temp[0];
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	ld	a, (hl)
	ld	-2 (ix), a
	C$aes192.c$124$4_0$39	= .
	.globl	C$aes192.c$124$4_0$39
;/work/source_code/aes192.c:124: temp[0] = temp[1];
	ld	a, -16 (ix)
	add	a, #0x01
	ld	-8 (ix), a
	ld	a, -15 (ix)
	adc	a, #0x00
	ld	-7 (ix), a
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, (hl)
	ld	-1 (ix), a
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	ld	a, -1 (ix)
	ld	(hl), a
	C$aes192.c$125$4_0$39	= .
	.globl	C$aes192.c$125$4_0$39
;/work/source_code/aes192.c:125: temp[1] = temp[2];
	ld	a, -16 (ix)
	add	a, #0x02
	ld	-6 (ix), a
	ld	a, -15 (ix)
	adc	a, #0x00
	ld	-5 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	a, (hl)
	ld	-1 (ix), a
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, -1 (ix)
	ld	(hl), a
	C$aes192.c$126$4_0$39	= .
	.globl	C$aes192.c$126$4_0$39
;/work/source_code/aes192.c:126: temp[2] = temp[3];
	ld	a, -16 (ix)
	add	a, #0x03
	ld	-8 (ix), a
	ld	a, -15 (ix)
	adc	a, #0x00
	ld	-7 (ix), a
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, (hl)
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	(hl), a
	C$aes192.c$127$4_0$39	= .
	.globl	C$aes192.c$127$4_0$39
;/work/source_code/aes192.c:127: temp[3] = t;
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, -2 (ix)
	ld	(hl), a
	C$aes192.c$130$2_0$32	= .
	.globl	C$aes192.c$130$2_0$32
;/work/source_code/aes192.c:130: for (j = 0; j < 4; j++) {
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00113$:
	C$aes192.c$131$6_0$41	= .
	.globl	C$aes192.c$131$6_0$41
;/work/source_code/aes192.c:131: temp[j] = sbox[temp[j]];
	ld	a, -16 (ix)
	add	a, -2 (ix)
	ld	-6 (ix), a
	ld	a, -15 (ix)
	adc	a, -1 (ix)
	ld	-5 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	c, (hl)
	ld	hl, #_sbox
	ld	b, #0x00
	add	hl, bc
	ld	a, (hl)
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	(hl), a
	C$aes192.c$130$5_0$40	= .
	.globl	C$aes192.c$130$5_0$40
;/work/source_code/aes192.c:130: for (j = 0; j < 4; j++) {
	inc	-2 (ix)
	jp	NZ, 00228$
	inc	-1 (ix)
00228$:
	ld	a, -2 (ix)
	sub	a, #0x04
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	C, 00113$
	C$aes192.c$134$4_0$39	= .
	.globl	C$aes192.c$134$4_0$39
;/work/source_code/aes192.c:134: temp[0] ^= rcon[i / key_words];
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	ld	c, (hl)
	push	bc
	ld	hl, #0x0006
	push	hl
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	hl
	call	__divsint
	pop	af
	pop	af
	pop	bc
	ld	de, #_rcon
	add	hl, de
	ld	a, (hl)
	xor	a, c
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	ld	(hl), a
	C$aes192.c$137$2_0$32	= .
	.globl	C$aes192.c$137$2_0$32
;/work/source_code/aes192.c:137: for (j = 0; j < 4; j++) {
00144$:
	ld	a, -4 (ix)
	add	a, #0x03
	ld	-14 (ix), a
	ld	a, -3 (ix)
	adc	a, #0x00
	ld	-13 (ix), a
	ld	a, -18 (ix)
	add	a, #0x03
	ld	-12 (ix), a
	ld	a, -17 (ix)
	adc	a, #0x00
	ld	-11 (ix), a
	ld	hl, #0x0004
	push	hl
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	hl
	call	__modsint
	pop	af
	pop	af
	ld	-10 (ix), l
	ld	-9 (ix), h
	ld	a, -17 (ix)
	rlca
	ld	a, #0x00
	rla
	ld	-8 (ix), a
	ld	hl, #0x0004
	push	hl
	ld	l, -18 (ix)
	ld	h, -17 (ix)
	push	hl
	call	__modsint
	pop	af
	pop	af
	ld	-7 (ix), l
	ld	-6 (ix), h
	ld	a, -3 (ix)
	rlca
	ld	a, #0x00
	rla
	ld	-5 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00115$:
	C$aes192.c$138$5_0$43	= .
	.globl	C$aes192.c$138$5_0$43
;/work/source_code/aes192.c:138: ctx->round_keys[i / 4][j][i % 4] =
	ld	e, -4 (ix)
	ld	h, -3 (ix)
	ld	a, -5 (ix)
	or	a, a
	jp	Z, 00127$
	ld	e, -14 (ix)
	ld	h, -13 (ix)
00127$:
	ld	l, e
	sra	h
	rr	l
	sra	h
	rr	l
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	e, -20 (ix)
	ld	d, -19 (ix)
	add	hl, de
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	sla	c
	rl	b
	sla	c
	rl	b
	add	hl, bc
	ld	a, l
	add	a, -10 (ix)
	ld	e, a
	ld	a, h
	adc	a, -9 (ix)
	ld	d, a
	C$aes192.c$139$5_0$43	= .
	.globl	C$aes192.c$139$5_0$43
;/work/source_code/aes192.c:139: (uint8_t)(ctx->round_keys[prev_key_word / 4][j][prev_key_word % 4] ^ temp[j]);
	ld	l, -18 (ix)
	ld	h, -17 (ix)
	ld	a, -8 (ix)
	or	a, a
	jp	Z, 00128$
	ld	l, -12 (ix)
	ld	h, -11 (ix)
00128$:
	sra	h
	rr	l
	sra	h
	rr	l
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	a, l
	add	a, -22 (ix)
	ld	l, a
	ld	a, h
	adc	a, -21 (ix)
	ld	h, a
	add	hl, bc
	ld	a, l
	add	a, -7 (ix)
	ld	c, a
	ld	a, h
	adc	a, -6 (ix)
	ld	b, a
	ld	a, -16 (ix)
	add	a, -2 (ix)
	ld	l, a
	ld	a, -15 (ix)
	adc	a, -1 (ix)
	ld	h, a
	ld	a, (hl)
	push	af
	ld	a, (bc)
	ld	c, a
	pop	af
	xor	a, c
	ld	(de), a
	C$aes192.c$137$4_0$42	= .
	.globl	C$aes192.c$137$4_0$42
;/work/source_code/aes192.c:137: for (j = 0; j < 4; j++) {
	inc	-2 (ix)
	jp	NZ, 00231$
	inc	-1 (ix)
00231$:
	ld	a, -2 (ix)
	sub	a, #0x04
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	C, 00115$
	C$aes192.c$113$2_0$35	= .
	.globl	C$aes192.c$113$2_0$35
;/work/source_code/aes192.c:113: for (i = key_words; i < 4 * (num_rounds + 1); i++) {
	inc	-4 (ix)
	jp	NZ, 00232$
	inc	-3 (ix)
00232$:
	jp	00118$
00120$:
	C$aes192.c$142$2_0$32	= .
	.globl	C$aes192.c$142$2_0$32
;/work/source_code/aes192.c:142: }
	ld	sp, ix
	pop	ix
	C$aes192.c$142$2_0$32	= .
	.globl	C$aes192.c$142$2_0$32
	XFaes192$key_expansion_192$0$0	= .
	.globl	XFaes192$key_expansion_192$0$0
	ret
	G$aes192_encrypt$0$0	= .
	.globl	G$aes192_encrypt$0$0
	C$aes192.c$144$2_0$45	= .
	.globl	C$aes192.c$144$2_0$45
;/work/source_code/aes192.c:144: void aes192_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *key) {
;	---------------------------------
; Function aes192_encrypt
; ---------------------------------
_aes192_encrypt::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-238
	add	hl, sp
	ld	sp, hl
	C$aes192.c$148$1_0$45	= .
	.globl	C$aes192.c$148$1_0$45
;/work/source_code/aes192.c:148: key_expansion_192(key, &ctx);
	ld	hl, #2
	add	hl, sp
	ld	-12 (ix), l
	ld	-11 (ix), h
	ld	c, -12 (ix)
	ld	b, -11 (ix)
	push	bc
	ld	l, 8 (ix)
	ld	h, 9 (ix)
	push	hl
	call	_key_expansion_192
	pop	af
	pop	af
	C$aes192.c$151$5_0$49	= .
	.globl	C$aes192.c$151$5_0$49
;/work/source_code/aes192.c:151: for (int i = 0; i < 4; i++) {
	ld	hl, #210
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	xor	a, a
	ld	-6 (ix), a
	ld	-5 (ix), a
00110$:
	ld	a, -6 (ix)
	sub	a, #0x04
	ld	a, -5 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00102$
	C$aes192.c$152$5_0$49	= .
	.globl	C$aes192.c$152$5_0$49
;/work/source_code/aes192.c:152: for (int j = 0; j < 4; j++) {
	ld	c, -6 (ix)
	ld	b, -5 (ix)
	sla	c
	rl	b
	sla	c
	rl	b
	ld	a, c
	ld	hl, #0
	add	hl, sp
	add	a, -2 (ix)
	ld	(hl), a
	ld	a, b
	adc	a, -1 (ix)
	inc	hl
	ld	(hl), a
	xor	a, a
	ld	-4 (ix), a
	ld	-3 (ix), a
00107$:
	ld	a, -4 (ix)
	sub	a, #0x04
	ld	a, -3 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00111$
	C$aes192.c$153$5_0$49	= .
	.globl	C$aes192.c$153$5_0$49
;/work/source_code/aes192.c:153: state[i][j] = plaintext[i + 4 * j];
	ld	iy, #0
	add	iy, sp
	ld	a, 0 (iy)
	add	a, -4 (ix)
	ld	-10 (ix), a
	ld	a, 1 (iy)
	adc	a, -3 (ix)
	ld	-9 (ix), a
	ld	a, -4 (ix)
	ld	-8 (ix), a
	ld	a, -3 (ix)
	ld	-7 (ix), a
	ld	a, #0x02+1
	jp	00181$
00180$:
	sla	-8 (ix)
	rl	-7 (ix)
00181$:
	dec	a
	jp	NZ, 00180$
	ld	a, -6 (ix)
	add	a, -8 (ix)
	ld	c, a
	ld	a, -5 (ix)
	adc	a, -7 (ix)
	ld	b, a
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, bc
	ld	a, (hl)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	(hl), a
	C$aes192.c$152$4_0$48	= .
	.globl	C$aes192.c$152$4_0$48
;/work/source_code/aes192.c:152: for (int j = 0; j < 4; j++) {
	inc	-4 (ix)
	jp	NZ, 00182$
	inc	-3 (ix)
00182$:
	jp	00107$
00111$:
	C$aes192.c$151$2_0$46	= .
	.globl	C$aes192.c$151$2_0$46
;/work/source_code/aes192.c:151: for (int i = 0; i < 4; i++) {
	inc	-6 (ix)
	jp	NZ, 00183$
	inc	-5 (ix)
00183$:
	jp	00110$
00102$:
	C$aes192.c$158$1_0$45	= .
	.globl	C$aes192.c$158$1_0$45
;/work/source_code/aes192.c:158: add_round_key(state, ctx.round_keys[0]);
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	ld	e, c
	ld	d, b
	push	bc
	push	hl
	push	de
	call	_add_round_key
	pop	af
	pop	af
	pop	bc
	C$aes192.c$161$3_0$51	= .
	.globl	C$aes192.c$161$3_0$51
;/work/source_code/aes192.c:161: for (int round = 1; round < AES192_NUM_ROUNDS; round++) {
	ld	a, -2 (ix)
	ld	-10 (ix), a
	ld	a, -1 (ix)
	ld	-9 (ix), a
	ld	a, -2 (ix)
	ld	-8 (ix), a
	ld	a, -1 (ix)
	ld	-7 (ix), a
	ld	a, -2 (ix)
	ld	-6 (ix), a
	ld	a, -1 (ix)
	ld	-5 (ix), a
	ld	a, -2 (ix)
	ld	-4 (ix), a
	ld	a, -1 (ix)
	ld	-3 (ix), a
	ld	-2 (ix), #0x01
	xor	a, a
	ld	-1 (ix), a
00113$:
	ld	a, -2 (ix)
	sub	a, #0x0c
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00103$
	C$aes192.c$162$3_0$51	= .
	.globl	C$aes192.c$162$3_0$51
;/work/source_code/aes192.c:162: sub_bytes(state);
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	push	bc
	push	de
	call	_sub_bytes
	pop	af
	pop	bc
	C$aes192.c$163$3_0$51	= .
	.globl	C$aes192.c$163$3_0$51
;/work/source_code/aes192.c:163: shift_rows(state);
	ld	e, -8 (ix)
	ld	d, -7 (ix)
	push	bc
	push	de
	call	_shift_rows
	pop	af
	pop	bc
	C$aes192.c$164$3_0$51	= .
	.globl	C$aes192.c$164$3_0$51
;/work/source_code/aes192.c:164: mix_columns(state);
	ld	e, -6 (ix)
	ld	d, -5 (ix)
	push	bc
	push	de
	call	_mix_columns
	pop	af
	pop	bc
	C$aes192.c$165$3_0$51	= .
	.globl	C$aes192.c$165$3_0$51
;/work/source_code/aes192.c:165: add_round_key(state, ctx.round_keys[round]);
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
	C$aes192.c$161$2_0$50	= .
	.globl	C$aes192.c$161$2_0$50
;/work/source_code/aes192.c:161: for (int round = 1; round < AES192_NUM_ROUNDS; round++) {
	inc	-2 (ix)
	jp	NZ, 00186$
	inc	-1 (ix)
00186$:
	jp	00113$
00103$:
	C$aes192.c$169$1_0$45	= .
	.globl	C$aes192.c$169$1_0$45
;/work/source_code/aes192.c:169: sub_bytes(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_sub_bytes
	pop	af
	pop	bc
	C$aes192.c$170$1_0$45	= .
	.globl	C$aes192.c$170$1_0$45
;/work/source_code/aes192.c:170: shift_rows(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_shift_rows
	pop	af
	pop	bc
	C$aes192.c$171$1_0$45	= .
	.globl	C$aes192.c$171$1_0$45
;/work/source_code/aes192.c:171: add_round_key(state, ctx.round_keys[AES192_NUM_ROUNDS]);
	ld	a, -12 (ix)
	add	a, #0xc0
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
	C$aes192.c$174$2_0$45	= .
	.globl	C$aes192.c$174$2_0$45
;/work/source_code/aes192.c:174: for (int i = 0; i < 4; i++) {
	xor	a, a
	ld	-4 (ix), a
	ld	-3 (ix), a
00119$:
	ld	a, -4 (ix)
	sub	a, #0x04
	ld	a, -3 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00121$
	C$aes192.c$175$5_0$55	= .
	.globl	C$aes192.c$175$5_0$55
;/work/source_code/aes192.c:175: for (int j = 0; j < 4; j++) {
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	add	hl, hl
	add	hl, hl
	add	hl, bc
	ld	-8 (ix), l
	ld	-7 (ix), h
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00116$:
	ld	a, -2 (ix)
	sub	a, #0x04
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00120$
	C$aes192.c$176$5_0$55	= .
	.globl	C$aes192.c$176$5_0$55
;/work/source_code/aes192.c:176: ciphertext[i + 4 * j] = state[i][j];
	ld	e, -2 (ix)
	ld	d, -1 (ix)
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, e
	add	a, -4 (ix)
	ld	e, a
	ld	a, d
	adc	a, -3 (ix)
	ld	d, a
	ld	a, 6 (ix)
	add	a, e
	ld	e, a
	ld	a, 7 (ix)
	adc	a, d
	ld	d, a
	ld	a, -8 (ix)
	add	a, -2 (ix)
	ld	-6 (ix), a
	ld	a, -7 (ix)
	adc	a, -1 (ix)
	ld	-5 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$175$4_0$54	= .
	.globl	C$aes192.c$175$4_0$54
;/work/source_code/aes192.c:175: for (int j = 0; j < 4; j++) {
	inc	-2 (ix)
	jp	NZ, 00189$
	inc	-1 (ix)
00189$:
	jp	00116$
00120$:
	C$aes192.c$174$2_0$52	= .
	.globl	C$aes192.c$174$2_0$52
;/work/source_code/aes192.c:174: for (int i = 0; i < 4; i++) {
	inc	-4 (ix)
	jp	NZ, 00190$
	inc	-3 (ix)
00190$:
	jp	00119$
00121$:
	C$aes192.c$179$2_0$45	= .
	.globl	C$aes192.c$179$2_0$45
;/work/source_code/aes192.c:179: }
	ld	sp, ix
	pop	ix
	C$aes192.c$179$2_0$45	= .
	.globl	C$aes192.c$179$2_0$45
	XG$aes192_encrypt$0$0	= .
	.globl	XG$aes192_encrypt$0$0
	ret
	G$main$0$0	= .
	.globl	G$main$0$0
	C$aes192.c$181$2_0$57	= .
	.globl	C$aes192.c$181$2_0$57
;/work/source_code/aes192.c:181: int main(void) {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-58
	add	hl, sp
	ld	sp, hl
	C$aes192.c$183$2_0$57	= .
	.globl	C$aes192.c$183$2_0$57
;/work/source_code/aes192.c:183: uint8_t plaintext[16] = {
	ld	hl, #0
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
	C$aes192.c$189$2_0$57	= .
	.globl	C$aes192.c$189$2_0$57
;/work/source_code/aes192.c:189: uint8_t key192[24] = {
	ld	hl, #16
	add	hl, sp
	ex	de, hl
	ld	a, #0x8e
	ld	(de), a
	ld	l, e
	ld	h, d
	inc	hl
	ld	(hl), #0x73
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	ld	(hl), #0xb0
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xf7
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0xda
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0x0e
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0x64
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0x52
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0xc8
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0x10
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0xf3
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0x2b
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0x80
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0x90
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x79
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0xe5
	ld	hl, #0x0010
	add	hl, de
	ld	(hl), #0x62
	ld	hl, #0x0011
	add	hl, de
	ld	(hl), #0xf8
	ld	hl, #0x0012
	add	hl, de
	ld	(hl), #0xea
	ld	hl, #0x0013
	add	hl, de
	ld	(hl), #0xd2
	ld	hl, #0x0014
	add	hl, de
	ld	(hl), #0x52
	ld	hl, #0x0015
	add	hl, de
	ld	(hl), #0x2c
	ld	hl, #0x0016
	add	hl, de
	ld	(hl), #0x6b
	ld	hl, #0x0017
	add	hl, de
	ld	(hl), #0x7b
	C$aes192.c$197$1_0$57	= .
	.globl	C$aes192.c$197$1_0$57
;/work/source_code/aes192.c:197: aes192_encrypt(plaintext, ciphertext, key192);
	ld	hl, #40
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	de
	push	hl
	push	bc
	call	_aes192_encrypt
	ld	hl, #6
	add	hl, sp
	ld	sp, hl
	C$aes192.c$199$1_0$57	= .
	.globl	C$aes192.c$199$1_0$57
;/work/source_code/aes192.c:199: printf("=== AES-192 ===\n");
	ld	hl, #___str_1
	push	hl
	call	_puts
	pop	af
	C$aes192.c$200$1_0$57	= .
	.globl	C$aes192.c$200$1_0$57
;/work/source_code/aes192.c:200: printf("Ciphertext: ");
	ld	hl, #___str_2
	push	hl
	call	_printf
	pop	af
	C$aes192.c$201$3_0$59	= .
	.globl	C$aes192.c$201$3_0$59
;/work/source_code/aes192.c:201: for (int i = 0; i < 16; i++) {
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00101$
	C$aes192.c$202$3_0$59	= .
	.globl	C$aes192.c$202$3_0$59
;/work/source_code/aes192.c:202: printf("%02x ", ciphertext[i]);
	ld	l, -2 (ix)
	ld	h, -1 (ix)
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
	C$aes192.c$201$2_0$58	= .
	.globl	C$aes192.c$201$2_0$58
;/work/source_code/aes192.c:201: for (int i = 0; i < 16; i++) {
	inc	bc
	jp	00103$
00101$:
	C$aes192.c$204$1_0$57	= .
	.globl	C$aes192.c$204$1_0$57
;/work/source_code/aes192.c:204: printf("\n");
	ld	hl, #___str_5
	push	hl
	call	_puts
	pop	af
	C$aes192.c$206$1_0$57	= .
	.globl	C$aes192.c$206$1_0$57
;/work/source_code/aes192.c:206: return 0;
	ld	hl, #0x0000
00105$:
	C$aes192.c$207$1_0$57	= .
	.globl	C$aes192.c$207$1_0$57
;/work/source_code/aes192.c:207: }
	ld	sp, ix
	pop	ix
	C$aes192.c$207$1_0$57	= .
	.globl	C$aes192.c$207$1_0$57
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Faes192$__str_1$0_0$0 == .
___str_1:
	.ascii "=== AES-192 ==="
	.db 0x00
Faes192$__str_2$0_0$0 == .
___str_2:
	.ascii "Ciphertext: "
	.db 0x00
Faes192$__str_3$0_0$0 == .
___str_3:
	.ascii "%02x "
	.db 0x00
Faes192$__str_5$0_0$0 == .
___str_5:
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
