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
	.globl _AES256_Encrypt
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
	C$aes256.c$33$0_0$35	= .
	.globl	C$aes256.c$33$0_0$35
;/work/source_code/testingfiles/aes256.c:33: static inline uint8_t xtime(uint8_t x) {
;	---------------------------------
; Function xtime
; ---------------------------------
_xtime:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes256.c$34$1_0$35	= .
	.globl	C$aes256.c$34$1_0$35
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	a, 4 (ix)
	add	a, a
	ld	c, a
	ld	a, 4 (ix)
	rlca
	jp	C,00110$
	jp	00103$
00110$:
	ld	de, #0x001b
	jp	00104$
00103$:
	ld	de, #0x0000
00104$:
	ld	a, c
	rla
	sbc	a, a
	push	af
	ld	a, c
	xor	a, e
	ld	l, a
	pop	af
	xor	a, d
00101$:
	C$aes256.c$35$1_0$35	= .
	.globl	C$aes256.c$35$1_0$35
;/work/source_code/testingfiles/aes256.c:35: }
	pop	ix
	C$aes256.c$35$1_0$35	= .
	.globl	C$aes256.c$35$1_0$35
	XFaes256$xtime$0$0	= .
	.globl	XFaes256$xtime$0$0
	ret
Faes256$SBOX$0_0$0 == .
_SBOX:
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
Faes256$RCON$0_0$0 == .
_RCON:
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
	Faes256$SubBytes$0$0	= .
	.globl	Faes256$SubBytes$0$0
	C$aes256.c$37$1_0$38	= .
	.globl	C$aes256.c$37$1_0$38
;/work/source_code/testingfiles/aes256.c:37: static void SubBytes(uint8_t *s) {
;	---------------------------------
; Function SubBytes
; ---------------------------------
_SubBytes:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes256.c$38$2_0$38	= .
	.globl	C$aes256.c$38$2_0$38
;/work/source_code/testingfiles/aes256.c:38: for (int i = 0; i < 16; ++i) s[i] = SBOX[s[i]];
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00105$
	ld	a, 4 (ix)
	add	a, c
	ld	e, a
	ld	a, 5 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	inc	bc
	jp	00103$
00105$:
	C$aes256.c$39$2_0$38	= .
	.globl	C$aes256.c$39$2_0$38
;/work/source_code/testingfiles/aes256.c:39: }
	pop	ix
	C$aes256.c$39$2_0$38	= .
	.globl	C$aes256.c$39$2_0$38
	XFaes256$SubBytes$0$0	= .
	.globl	XFaes256$SubBytes$0$0
	ret
	Faes256$ShiftRows$0$0	= .
	.globl	Faes256$ShiftRows$0$0
	C$aes256.c$41$2_0$40	= .
	.globl	C$aes256.c$41$2_0$40
;/work/source_code/testingfiles/aes256.c:41: static void ShiftRows(uint8_t *s) {
;	---------------------------------
; Function ShiftRows
; ---------------------------------
_ShiftRows:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-16
	add	hl, sp
	ld	sp, hl
	C$aes256.c$43$1_0$40	= .
	.globl	C$aes256.c$43$1_0$40
;/work/source_code/testingfiles/aes256.c:43: memcpy(t, s, 16);
	ld	hl, #0
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
	C$aes256.c$44$1_0$40	= .
	.globl	C$aes256.c$44$1_0$40
;/work/source_code/testingfiles/aes256.c:44: s[1]  = t[5];  s[5]  = t[9];  s[9]  = t[13]; s[13] = t[1];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x05
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x0009
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x09
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000d
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0d
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	inc	hl
	ld	a, (hl)
	ld	(de), a
	C$aes256.c$45$1_0$40	= .
	.globl	C$aes256.c$45$1_0$40
;/work/source_code/testingfiles/aes256.c:45: s[2]  = t[10]; s[10] = t[2];  s[6]  = t[14]; s[14] = t[6];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	inc	de
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000a
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0a
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x06
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000e
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0e
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x0006
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	C$aes256.c$46$1_0$40	= .
	.globl	C$aes256.c$46$1_0$40
;/work/source_code/testingfiles/aes256.c:46: s[3]  = t[15]; s[7]  = t[3];  s[11] = t[7];  s[15] = t[11];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	inc	de
	inc	de
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000f
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x07
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0b
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x0007
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0f
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	ld	bc, #0x000b
	add	hl, bc
	ld	a, (hl)
	ld	(de), a
00101$:
	C$aes256.c$47$1_0$40	= .
	.globl	C$aes256.c$47$1_0$40
;/work/source_code/testingfiles/aes256.c:47: }
	ld	sp, ix
	pop	ix
	C$aes256.c$47$1_0$40	= .
	.globl	C$aes256.c$47$1_0$40
	XFaes256$ShiftRows$0$0	= .
	.globl	XFaes256$ShiftRows$0$0
	ret
	Faes256$MixColumns$0$0	= .
	.globl	Faes256$MixColumns$0$0
	C$aes256.c$49$1_0$43	= .
	.globl	C$aes256.c$49$1_0$43
;/work/source_code/testingfiles/aes256.c:49: static void MixColumns(uint8_t *s) {
;	---------------------------------
; Function MixColumns
; ---------------------------------
_MixColumns:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-24
	add	hl, sp
	ld	sp, hl
	C$aes256.c$50$2_0$43	= .
	.globl	C$aes256.c$50$2_0$43
;/work/source_code/testingfiles/aes256.c:50: for (int i = 0; i < 4; ++i) {
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00111$:
	ld	a, -2 (ix)
	sub	a, #0x04
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00113$
	C$aes256.c$51$3_0$44	= .
	.globl	C$aes256.c$51$3_0$44
;/work/source_code/testingfiles/aes256.c:51: int a = 4 * i;
	ld	e, -2 (ix)
	ld	d, -1 (ix)
	sla	e
	rl	d
	sla	e
	rl	d
	C$aes256.c$52$3_0$44	= .
	.globl	C$aes256.c$52$3_0$44
;/work/source_code/testingfiles/aes256.c:52: uint8_t x0 = s[a], x1 = s[a+1], x2 = s[a+2], x3 = s[a+3];
	ld	a, 4 (ix)
	add	a, e
	ld	-4 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-3 (ix), a
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, (hl)
	ld	-24 (ix), a
	ld	c, e
	ld	b, d
	inc	bc
	ld	a, 4 (ix)
	add	a, c
	ld	c, a
	ld	a, 5 (ix)
	adc	a, b
	ld	b, a
	ld	a, (bc)
	ld	-23 (ix), a
	ld	hl, #0x0002
	add	hl, de
	ld	-6 (ix), l
	ld	-5 (ix), h
	ld	a, 4 (ix)
	add	a, -6 (ix)
	ld	-22 (ix), a
	ld	a, 5 (ix)
	adc	a, -5 (ix)
	ld	-21 (ix), a
	ld	l, -22 (ix)
	ld	h, -21 (ix)
	ld	a, (hl)
	ld	-20 (ix), a
	inc	de
	inc	de
	inc	de
	ld	a, 4 (ix)
	add	a, e
	ld	-19 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-18 (ix), a
	ld	l, -19 (ix)
	ld	h, -18 (ix)
	ld	a, (hl)
	ld	-17 (ix), a
	C$aes256.c$53$3_0$44	= .
	.globl	C$aes256.c$53$3_0$44
;/work/source_code/testingfiles/aes256.c:53: s[a]   = xtime(x0) ^ xtime(x1) ^ x1 ^ x2 ^ x3;
	ld	a, -4 (ix)
	ld	-8 (ix), a
	ld	a, -3 (ix)
	ld	-7 (ix), a
	C$aes256.c$34$2_0$43	= .
	.globl	C$aes256.c$34$2_0$43
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	a, -24 (ix)
	add	a, a
	ld	l, a
	ld	a, -24 (ix)
	and	a, #0x80
	ld	-16 (ix), a
	ld	-15 (ix), #0x00
	ld	a, -15 (ix)
	or	a, -16 (ix)
	jp	Z, 00115$
	ld	de, #0x001b
	jp	00116$
00115$:
	ld	de, #0x0000
00116$:
	ld	a, l
	ld	-14 (ix), a
	rla
	sbc	a, a
	ld	-13 (ix), a
	ld	a, e
	xor	a, -14 (ix)
	ld	e, a
	ld	a, d
	xor	a, -13 (ix)
	ld	d, a
	ld	-6 (ix), e
	ld	a, -23 (ix)
	add	a, a
	ld	-5 (ix), a
	ld	a, -23 (ix)
	and	a, #0x80
	ld	e, a
	ld	d, #0x00
	ld	a, d
	or	a, e
	jp	Z, 00117$
	ld	hl, #0x001b
	jp	00118$
00117$:
	ld	hl, #0x0000
00118$:
	ld	a, -5 (ix)
	ld	-4 (ix), a
	rla
	sbc	a, a
	ld	-3 (ix), a
	ld	a, l
	xor	a, -4 (ix)
	ld	l, a
	ld	a, h
	xor	a, -3 (ix)
	ld	h, a
	ld	a, l
	C$aes256.c$53$5_0$49	= .
	.globl	C$aes256.c$53$5_0$49
;/work/source_code/testingfiles/aes256.c:53: s[a]   = xtime(x0) ^ xtime(x1) ^ x1 ^ x2 ^ x3;
	xor	a, -6 (ix)
	xor	a, -23 (ix)
	xor	a, -20 (ix)
	xor	a, -17 (ix)
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), a
	C$aes256.c$34$6_0$53	= .
	.globl	C$aes256.c$34$6_0$53
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	l, -5 (ix)
	ld	a, d
	or	a, e
	jp	Z, 00119$
	ld	de, #0x001b
	jp	00120$
00119$:
	ld	de, #0x0000
00120$:
	ld	a, l
	rla
	sbc	a, a
	push	af
	ld	a, e
	xor	a, l
	ld	e, a
	pop	af
	xor	a, d
	ld	d, a
	ld	a, e
	C$aes256.c$54$5_0$52	= .
	.globl	C$aes256.c$54$5_0$52
;/work/source_code/testingfiles/aes256.c:54: s[a+1] = x0 ^ xtime(x1) ^ xtime(x2) ^ x2 ^ x3;
	xor	a, -24 (ix)
	ld	-6 (ix), a
	C$aes256.c$34$6_0$56	= .
	.globl	C$aes256.c$34$6_0$56
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	a, -20 (ix)
	add	a, a
	ld	-5 (ix), a
	ld	a, -20 (ix)
	and	a, #0x80
	ld	e, a
	ld	d, #0x00
	ld	a, d
	or	a, e
	jp	Z, 00121$
	ld	hl, #0x001b
	jp	00122$
00121$:
	ld	hl, #0x0000
00122$:
	ld	a, -5 (ix)
	ld	-4 (ix), a
	rla
	sbc	a, a
	ld	-3 (ix), a
	ld	a, l
	xor	a, -4 (ix)
	ld	l, a
	ld	a, h
	xor	a, -3 (ix)
	ld	h, a
	ld	a, l
	C$aes256.c$54$5_0$55	= .
	.globl	C$aes256.c$54$5_0$55
;/work/source_code/testingfiles/aes256.c:54: s[a+1] = x0 ^ xtime(x1) ^ xtime(x2) ^ x2 ^ x3;
	xor	a, -6 (ix)
	xor	a, -20 (ix)
	xor	a, -17 (ix)
	ld	(bc), a
	C$aes256.c$55$3_0$44	= .
	.globl	C$aes256.c$55$3_0$44
;/work/source_code/testingfiles/aes256.c:55: s[a+2] = x0 ^ x1 ^ xtime(x2) ^ xtime(x3) ^ x3;
	ld	a, -24 (ix)
	xor	a, -23 (ix)
	ld	c, a
	C$aes256.c$34$6_0$59	= .
	.globl	C$aes256.c$34$6_0$59
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	l, -5 (ix)
	ld	a, d
	or	a, e
	jp	Z, 00123$
	ld	de, #0x001b
	jp	00124$
00123$:
	ld	de, #0x0000
00124$:
	ld	a, l
	rla
	sbc	a, a
	push	af
	ld	a, e
	xor	a, l
	ld	e, a
	pop	af
	xor	a, d
	ld	d, a
	ld	a, e
	C$aes256.c$55$5_0$58	= .
	.globl	C$aes256.c$55$5_0$58
;/work/source_code/testingfiles/aes256.c:55: s[a+2] = x0 ^ x1 ^ xtime(x2) ^ xtime(x3) ^ x3;
	xor	a, c
	ld	-12 (ix), a
	C$aes256.c$34$6_0$62	= .
	.globl	C$aes256.c$34$6_0$62
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	a, -17 (ix)
	add	a, a
	ld	-11 (ix), a
	ld	a, -17 (ix)
	and	a, #0x80
	ld	-10 (ix), a
	ld	-9 (ix), #0x00
	ld	a, -9 (ix)
	or	a, -10 (ix)
	jp	Z, 00125$
	ld	-8 (ix), #0x1b
	xor	a, a
	ld	-7 (ix), a
	jp	00126$
00125$:
	xor	a, a
	ld	-8 (ix), a
	ld	-7 (ix), a
00126$:
	ld	a, -11 (ix)
	ld	-6 (ix), a
	rla
	sbc	a, a
	ld	-5 (ix), a
	ld	a, -6 (ix)
	xor	a, -8 (ix)
	ld	-4 (ix), a
	ld	a, -5 (ix)
	xor	a, -7 (ix)
	ld	-3 (ix), a
	ld	a, -4 (ix)
	ld	-3 (ix), a
	C$aes256.c$55$5_0$61	= .
	.globl	C$aes256.c$55$5_0$61
;/work/source_code/testingfiles/aes256.c:55: s[a+2] = x0 ^ x1 ^ xtime(x2) ^ xtime(x3) ^ x3;
	ld	a, -3 (ix)
	xor	a, -12 (ix)
	ld	-3 (ix), a
	ld	a, -3 (ix)
	xor	a, -17 (ix)
	ld	-3 (ix), a
	pop	bc
	pop	hl
	push	hl
	push	bc
	ld	a, -3 (ix)
	ld	(hl), a
	C$aes256.c$34$6_0$65	= .
	.globl	C$aes256.c$34$6_0$65
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	a, -15 (ix)
	or	a, -16 (ix)
	jp	Z, 00127$
	ld	-6 (ix), #0x1b
	xor	a, a
	ld	-5 (ix), a
	jp	00128$
00127$:
	xor	a, a
	ld	-6 (ix), a
	ld	-5 (ix), a
00128$:
	ld	a, -14 (ix)
	xor	a, -6 (ix)
	ld	-4 (ix), a
	ld	a, -13 (ix)
	xor	a, -5 (ix)
	ld	-3 (ix), a
	ld	a, -4 (ix)
	ld	-3 (ix), a
	C$aes256.c$56$5_0$64	= .
	.globl	C$aes256.c$56$5_0$64
;/work/source_code/testingfiles/aes256.c:56: s[a+3] = xtime(x0) ^ x0 ^ x1 ^ x2 ^ xtime(x3);
	ld	a, -3 (ix)
	xor	a, -24 (ix)
	ld	-3 (ix), a
	ld	a, -3 (ix)
	xor	a, -23 (ix)
	ld	-3 (ix), a
	ld	a, -3 (ix)
	xor	a, -20 (ix)
	ld	-3 (ix), a
	C$aes256.c$34$6_0$68	= .
	.globl	C$aes256.c$34$6_0$68
;/work/source_code/testingfiles/aes256.c:34: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	a, -11 (ix)
	ld	-4 (ix), a
	ld	a, -9 (ix)
	or	a, -10 (ix)
	jp	Z, 00129$
	ld	-6 (ix), #0x1b
	xor	a, a
	ld	-5 (ix), a
	jp	00130$
00129$:
	xor	a, a
	ld	-6 (ix), a
	ld	-5 (ix), a
00130$:
	ld	a, -4 (ix)
	ld	c, a
	rla
	sbc	a, a
	push	af
	ld	a, c
	xor	a, -6 (ix)
	ld	c, a
	pop	af
	xor	a, -5 (ix)
	C$aes256.c$56$5_0$67	= .
	.globl	C$aes256.c$56$5_0$67
;/work/source_code/testingfiles/aes256.c:56: s[a+3] = xtime(x0) ^ x0 ^ x1 ^ x2 ^ xtime(x3);
	ld	a, -3 (ix)
	xor	a, c
	ld	l, -19 (ix)
	ld	h, -18 (ix)
	ld	(hl), a
	C$aes256.c$50$2_0$43	= .
	.globl	C$aes256.c$50$2_0$43
;/work/source_code/testingfiles/aes256.c:50: for (int i = 0; i < 4; ++i) {
	inc	-2 (ix)
	jp	NZ, 00184$
	inc	-1 (ix)
00184$:
	jp	00111$
00113$:
	C$aes256.c$58$2_0$43	= .
	.globl	C$aes256.c$58$2_0$43
;/work/source_code/testingfiles/aes256.c:58: }
	ld	sp, ix
	pop	ix
	C$aes256.c$58$2_0$43	= .
	.globl	C$aes256.c$58$2_0$43
	XFaes256$MixColumns$0$0	= .
	.globl	XFaes256$MixColumns$0$0
	ret
	Faes256$AddRoundKey$0$0	= .
	.globl	Faes256$AddRoundKey$0$0
	C$aes256.c$60$2_0$71	= .
	.globl	C$aes256.c$60$2_0$71
;/work/source_code/testingfiles/aes256.c:60: static void AddRoundKey(uint8_t *s, const uint8_t *rk) {
;	---------------------------------
; Function AddRoundKey
; ---------------------------------
_AddRoundKey:
	push	ix
	ld	ix,#0
	add	ix,sp
	dec	sp
	C$aes256.c$61$2_0$71	= .
	.globl	C$aes256.c$61$2_0$71
;/work/source_code/testingfiles/aes256.c:61: for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00105$
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
	inc	bc
	jp	00103$
00105$:
	C$aes256.c$62$2_0$71	= .
	.globl	C$aes256.c$62$2_0$71
;/work/source_code/testingfiles/aes256.c:62: }
	inc	sp
	pop	ix
	C$aes256.c$62$2_0$71	= .
	.globl	C$aes256.c$62$2_0$71
	XFaes256$AddRoundKey$0$0	= .
	.globl	XFaes256$AddRoundKey$0$0
	ret
	Faes256$RotWord$0$0	= .
	.globl	Faes256$RotWord$0$0
	C$aes256.c$65$2_0$73	= .
	.globl	C$aes256.c$65$2_0$73
;/work/source_code/testingfiles/aes256.c:65: static void RotWord(uint8_t *w) {
;	---------------------------------
; Function RotWord
; ---------------------------------
_RotWord:
	push	ix
	ld	ix,#0
	add	ix,sp
	push	af
	dec	sp
	C$aes256.c$66$1_0$73	= .
	.globl	C$aes256.c$66$1_0$73
;/work/source_code/testingfiles/aes256.c:66: uint8_t t = w[0];
	ld	c, 4 (ix)
	ld	b, 5 (ix)
	ld	a, (bc)
	ld	-3 (ix), a
	C$aes256.c$67$1_0$73	= .
	.globl	C$aes256.c$67$1_0$73
;/work/source_code/testingfiles/aes256.c:67: w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = t;
	ld	e, c
	ld	d, b
	inc	de
	ld	a, (de)
	ld	(bc), a
	ld	hl, #0x0002
	add	hl, bc
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	a, (hl)
	ld	(de), a
	inc	bc
	inc	bc
	inc	bc
	ld	a, (bc)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	ld	a, -3 (ix)
	ld	(bc), a
00101$:
	C$aes256.c$68$1_0$73	= .
	.globl	C$aes256.c$68$1_0$73
;/work/source_code/testingfiles/aes256.c:68: }
	ld	sp, ix
	pop	ix
	C$aes256.c$68$1_0$73	= .
	.globl	C$aes256.c$68$1_0$73
	XFaes256$RotWord$0$0	= .
	.globl	XFaes256$RotWord$0$0
	ret
	Faes256$SubWord$0$0	= .
	.globl	Faes256$SubWord$0$0
	C$aes256.c$71$1_0$75	= .
	.globl	C$aes256.c$71$1_0$75
;/work/source_code/testingfiles/aes256.c:71: static void SubWord(uint8_t *w) {
;	---------------------------------
; Function SubWord
; ---------------------------------
_SubWord:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes256.c$72$1_0$75	= .
	.globl	C$aes256.c$72$1_0$75
;/work/source_code/testingfiles/aes256.c:72: w[0] = SBOX[w[0]]; w[1] = SBOX[w[1]];
	ld	c, 4 (ix)
	ld	b, 5 (ix)
	ld	a, (bc)
	add	a, #<(_SBOX)
	ld	e, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	d, a
	ld	a, (de)
	ld	(bc), a
	ld	e, c
	ld	d, b
	inc	de
	ld	a, (de)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	C$aes256.c$73$1_0$75	= .
	.globl	C$aes256.c$73$1_0$75
;/work/source_code/testingfiles/aes256.c:73: w[2] = SBOX[w[2]]; w[3] = SBOX[w[3]];
	ld	e, c
	ld	d, b
	inc	de
	inc	de
	ld	a, (de)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	inc	bc
	inc	bc
	inc	bc
	ld	a, (bc)
	add	a, #<(_SBOX)
	ld	e, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	d, a
	ld	a, (de)
	ld	(bc), a
00101$:
	C$aes256.c$74$1_0$75	= .
	.globl	C$aes256.c$74$1_0$75
;/work/source_code/testingfiles/aes256.c:74: }
	pop	ix
	C$aes256.c$74$1_0$75	= .
	.globl	C$aes256.c$74$1_0$75
	XFaes256$SubWord$0$0	= .
	.globl	XFaes256$SubWord$0$0
	ret
	Faes256$KeyExpansion$0$0	= .
	.globl	Faes256$KeyExpansion$0$0
	C$aes256.c$77$1_0$77	= .
	.globl	C$aes256.c$77$1_0$77
;/work/source_code/testingfiles/aes256.c:77: static void KeyExpansion(const uint8_t key[32], uint8_t roundKeys[EXPANDED_KEY_BYTES]) {
;	---------------------------------
; Function KeyExpansion
; ---------------------------------
_KeyExpansion:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-18
	add	hl, sp
	ld	sp, hl
	C$aes256.c$78$1_0$77	= .
	.globl	C$aes256.c$78$1_0$77
;/work/source_code/testingfiles/aes256.c:78: memcpy(roundKeys, key, 32);
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	ld	bc, #0x0020
	ldir
	C$aes256.c$79$2_0$78	= .
	.globl	C$aes256.c$79$2_0$78
;/work/source_code/testingfiles/aes256.c:79: int bytes = 32;
	ld	-14 (ix), #0x20
	xor	a, a
	ld	-13 (ix), a
	C$aes256.c$83$3_1$80	= .
	.globl	C$aes256.c$83$3_1$80
;/work/source_code/testingfiles/aes256.c:83: while (bytes < EXPANDED_KEY_BYTES) {
	ld	hl, #0
	add	hl, sp
	ld	-12 (ix), l
	ld	-11 (ix), h
	ld	a, -12 (ix)
	ld	-10 (ix), a
	ld	a, -11 (ix)
	ld	-9 (ix), a
	ld	a, -12 (ix)
	ld	-8 (ix), a
	ld	a, -11 (ix)
	ld	-7 (ix), a
	ld	-6 (ix), #0x01
	xor	a, a
	ld	-5 (ix), a
00109$:
	ld	a, -14 (ix)
	sub	a, #0xf0
	ld	a, -13 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00118$
	C$aes256.c$85$3_1$80	= .
	.globl	C$aes256.c$85$3_1$80
;/work/source_code/testingfiles/aes256.c:85: for (int i = 0; i < 4; ++i) temp[i] = roundKeys[bytes - 4 + i];
	ld	a, -14 (ix)
	add	a, #0xfc
	ld	-4 (ix), a
	ld	a, -13 (ix)
	adc	a, #0xff
	ld	-3 (ix), a
	ld	bc, #0x0000
00113$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00101$
	ld	a, -12 (ix)
	add	a, c
	ld	-2 (ix), a
	ld	a, -11 (ix)
	adc	a, b
	ld	-1 (ix), a
	ld	a, -4 (ix)
	add	a, c
	ld	e, a
	ld	a, -3 (ix)
	adc	a, b
	ld	d, a
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	inc	bc
	jp	00113$
00101$:
	C$aes256.c$87$1_1$77	= .
	.globl	C$aes256.c$87$1_1$77
;/work/source_code/testingfiles/aes256.c:87: if (bytes % (Nk * 4) == 0) {
	ld	hl, #0x0020
	push	hl
	ld	l, -14 (ix)
	ld	h, -13 (ix)
	push	hl
	call	__modsint
	pop	af
	pop	af
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -1 (ix)
	or	a, -2 (ix)
	jp	NZ, 00104$
	C$aes256.c$88$3_1$81	= .
	.globl	C$aes256.c$88$3_1$81
;/work/source_code/testingfiles/aes256.c:88: RotWord(temp);
	ld	c, -12 (ix)
	ld	b, -11 (ix)
	push	bc
	call	_RotWord
	pop	af
	C$aes256.c$89$3_1$81	= .
	.globl	C$aes256.c$89$3_1$81
;/work/source_code/testingfiles/aes256.c:89: SubWord(temp);
	ld	c, -12 (ix)
	ld	b, -11 (ix)
	push	bc
	call	_SubWord
	pop	af
	C$aes256.c$90$3_1$81	= .
	.globl	C$aes256.c$90$3_1$81
;/work/source_code/testingfiles/aes256.c:90: temp[0] ^= RCON[rcon_idx++];
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	c, (hl)
	ld	a, #<(_RCON)
	add	a, -6 (ix)
	ld	e, a
	ld	a, #>(_RCON)
	adc	a, -5 (ix)
	ld	d, a
	inc	-6 (ix)
	jp	NZ, 00162$
	inc	-5 (ix)
00162$:
	ld	a, (de)
	xor	a, c
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	(hl), a
	jp	00127$
	C$aes256.c$91$2_1$79	= .
	.globl	C$aes256.c$91$2_1$79
;/work/source_code/testingfiles/aes256.c:91: } else if (Nk > 6 && (bytes % (Nk * 4) == 16)) {
00104$:
	ld	a, -2 (ix)
	sub	a, #0x10
	or	a, -1 (ix)
	jp	NZ,00163$
	jp	00164$
00163$:
	jp	00127$
00164$:
	C$aes256.c$93$3_1$82	= .
	.globl	C$aes256.c$93$3_1$82
;/work/source_code/testingfiles/aes256.c:93: SubWord(temp);
	ld	c, -10 (ix)
	ld	b, -9 (ix)
	push	bc
	call	_SubWord
	pop	af
	C$aes256.c$96$1_1$77	= .
	.globl	C$aes256.c$96$1_1$77
;/work/source_code/testingfiles/aes256.c:96: for (int i = 0; i < 4; ++i) {
00127$:
	ld	a, -14 (ix)
	ld	-4 (ix), a
	ld	a, -13 (ix)
	ld	-3 (ix), a
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
	jp	NC, 00109$
	C$aes256.c$97$4_1$84	= .
	.globl	C$aes256.c$97$4_1$84
;/work/source_code/testingfiles/aes256.c:97: roundKeys[bytes] = roundKeys[bytes - (Nk * 4)] ^ temp[i];
	ld	a, 6 (ix)
	add	a, -4 (ix)
	ld	c, a
	ld	a, 7 (ix)
	adc	a, -3 (ix)
	ld	b, a
	ld	a, -4 (ix)
	add	a, #0xe0
	ld	e, a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	d, a
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, de
	ld	e, (hl)
	ld	a, -8 (ix)
	add	a, -2 (ix)
	ld	l, a
	ld	a, -7 (ix)
	adc	a, -1 (ix)
	ld	h, a
	ld	a, (hl)
	xor	a, e
	ld	(bc), a
	C$aes256.c$98$4_1$84	= .
	.globl	C$aes256.c$98$4_1$84
;/work/source_code/testingfiles/aes256.c:98: ++bytes;
	inc	-4 (ix)
	jp	NZ, 00165$
	inc	-3 (ix)
00165$:
	ld	a, -4 (ix)
	ld	-14 (ix), a
	ld	a, -3 (ix)
	ld	-13 (ix), a
	C$aes256.c$96$3_1$83	= .
	.globl	C$aes256.c$96$3_1$83
;/work/source_code/testingfiles/aes256.c:96: for (int i = 0; i < 4; ++i) {
	inc	-2 (ix)
	jp	NZ, 00166$
	inc	-1 (ix)
00166$:
	jp	00116$
00118$:
	C$aes256.c$101$1_1$77	= .
	.globl	C$aes256.c$101$1_1$77
;/work/source_code/testingfiles/aes256.c:101: }
	ld	sp, ix
	pop	ix
	C$aes256.c$101$1_1$77	= .
	.globl	C$aes256.c$101$1_1$77
	XFaes256$KeyExpansion$0$0	= .
	.globl	XFaes256$KeyExpansion$0$0
	ret
	G$AES256_Encrypt$0$0	= .
	.globl	G$AES256_Encrypt$0$0
	C$aes256.c$103$1_1$86	= .
	.globl	C$aes256.c$103$1_1$86
;/work/source_code/testingfiles/aes256.c:103: void AES256_Encrypt(const uint8_t in[16], uint8_t out[16], const uint8_t key[32]) {
;	---------------------------------
; Function AES256_Encrypt
; ---------------------------------
_AES256_Encrypt::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-268
	add	hl, sp
	ld	sp, hl
	C$aes256.c$107$1_0$86	= .
	.globl	C$aes256.c$107$1_0$86
;/work/source_code/testingfiles/aes256.c:107: memcpy(state, in, 16);
	ld	hl, #0
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
	C$aes256.c$108$1_0$86	= .
	.globl	C$aes256.c$108$1_0$86
;/work/source_code/testingfiles/aes256.c:108: KeyExpansion(key, roundKeys);
	ld	hl, #16
	add	hl, sp
	ld	-12 (ix), l
	ld	-11 (ix), h
	ld	e, -12 (ix)
	ld	d, -11 (ix)
	push	bc
	push	de
	ld	l, 8 (ix)
	ld	h, 9 (ix)
	push	hl
	call	_KeyExpansion
	pop	af
	pop	af
	pop	bc
	C$aes256.c$110$1_0$86	= .
	.globl	C$aes256.c$110$1_0$86
;/work/source_code/testingfiles/aes256.c:110: AddRoundKey(state, roundKeys + 0);
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	e, c
	ld	d, b
	push	bc
	push	hl
	push	de
	call	_AddRoundKey
	pop	af
	pop	af
	pop	bc
	C$aes256.c$112$3_0$88	= .
	.globl	C$aes256.c$112$3_0$88
;/work/source_code/testingfiles/aes256.c:112: for (int round = 1; round < Nr; ++round) {
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
	jp	NC, 00101$
	C$aes256.c$113$3_0$88	= .
	.globl	C$aes256.c$113$3_0$88
;/work/source_code/testingfiles/aes256.c:113: SubBytes(state);
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	push	bc
	push	de
	call	_SubBytes
	pop	af
	pop	bc
	C$aes256.c$114$3_0$88	= .
	.globl	C$aes256.c$114$3_0$88
;/work/source_code/testingfiles/aes256.c:114: ShiftRows(state);
	ld	e, -8 (ix)
	ld	d, -7 (ix)
	push	bc
	push	de
	call	_ShiftRows
	pop	af
	pop	bc
	C$aes256.c$115$3_0$88	= .
	.globl	C$aes256.c$115$3_0$88
;/work/source_code/testingfiles/aes256.c:115: MixColumns(state);
	ld	e, -6 (ix)
	ld	d, -5 (ix)
	push	bc
	push	de
	call	_MixColumns
	pop	af
	pop	bc
	C$aes256.c$116$3_0$88	= .
	.globl	C$aes256.c$116$3_0$88
;/work/source_code/testingfiles/aes256.c:116: AddRoundKey(state, roundKeys + (16 * round));
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
	call	_AddRoundKey
	pop	af
	pop	af
	pop	bc
	C$aes256.c$112$2_0$87	= .
	.globl	C$aes256.c$112$2_0$87
;/work/source_code/testingfiles/aes256.c:112: for (int round = 1; round < Nr; ++round) {
	inc	-2 (ix)
	jp	NZ, 00120$
	inc	-1 (ix)
00120$:
	jp	00103$
00101$:
	C$aes256.c$119$1_0$86	= .
	.globl	C$aes256.c$119$1_0$86
;/work/source_code/testingfiles/aes256.c:119: SubBytes(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_SubBytes
	pop	af
	pop	bc
	C$aes256.c$120$1_0$86	= .
	.globl	C$aes256.c$120$1_0$86
;/work/source_code/testingfiles/aes256.c:120: ShiftRows(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_ShiftRows
	pop	af
	pop	bc
	C$aes256.c$121$1_0$86	= .
	.globl	C$aes256.c$121$1_0$86
;/work/source_code/testingfiles/aes256.c:121: AddRoundKey(state, roundKeys + (16 * Nr));
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
	call	_AddRoundKey
	pop	af
	pop	af
	pop	bc
	C$aes256.c$123$1_0$86	= .
	.globl	C$aes256.c$123$1_0$86
;/work/source_code/testingfiles/aes256.c:123: memcpy(out, state, 16);
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	l, c
	ld	h, b
	ld	bc, #0x0010
	ldir
00105$:
	C$aes256.c$124$1_0$86	= .
	.globl	C$aes256.c$124$1_0$86
;/work/source_code/testingfiles/aes256.c:124: }
	ld	sp, ix
	pop	ix
	C$aes256.c$124$1_0$86	= .
	.globl	C$aes256.c$124$1_0$86
	XG$AES256_Encrypt$0$0	= .
	.globl	XG$AES256_Encrypt$0$0
	ret
	G$main$0$0	= .
	.globl	G$main$0$0
	C$aes256.c$126$1_0$90	= .
	.globl	C$aes256.c$126$1_0$90
;/work/source_code/testingfiles/aes256.c:126: int main(void) {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-66
	add	hl, sp
	ld	sp, hl
	C$aes256.c$128$2_0$90	= .
	.globl	C$aes256.c$128$2_0$90
;/work/source_code/testingfiles/aes256.c:128: uint8_t key[32] = {
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
	C$aes256.c$135$2_0$90	= .
	.globl	C$aes256.c$135$2_0$90
;/work/source_code/testingfiles/aes256.c:135: uint8_t plaintext[16] = {
	ld	hl, #32
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	a, #0x6b
	ld	(bc), a
	ld	l, c
	ld	h, b
	inc	hl
	ld	(hl), #0xc1
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	(hl), #0xbe
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xe2
	ld	hl, #0x0004
	add	hl, bc
	ld	(hl), #0x2e
	ld	hl, #0x0005
	add	hl, bc
	ld	(hl), #0x40
	ld	hl, #0x0006
	add	hl, bc
	ld	(hl), #0x9f
	ld	hl, #0x0007
	add	hl, bc
	ld	(hl), #0x96
	ld	hl, #0x0008
	add	hl, bc
	ld	(hl), #0xe9
	ld	hl, #0x0009
	add	hl, bc
	ld	(hl), #0x3d
	ld	hl, #0x000a
	add	hl, bc
	ld	(hl), #0x7e
	ld	hl, #0x000b
	add	hl, bc
	ld	(hl), #0x11
	ld	hl, #0x000c
	add	hl, bc
	ld	(hl), #0x73
	ld	hl, #0x000d
	add	hl, bc
	ld	(hl), #0x93
	ld	hl, #0x000e
	add	hl, bc
	ld	(hl), #0x17
	ld	hl, #0x000f
	add	hl, bc
	ld	(hl), #0x2a
	C$aes256.c$142$1_0$90	= .
	.globl	C$aes256.c$142$1_0$90
;/work/source_code/testingfiles/aes256.c:142: AES256_Encrypt(plaintext, ciphertext, key);
	ld	hl, #48
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	de
	push	hl
	push	bc
	call	_AES256_Encrypt
	ld	hl, #6
	add	hl, sp
	ld	sp, hl
	C$aes256.c$144$1_0$90	= .
	.globl	C$aes256.c$144$1_0$90
;/work/source_code/testingfiles/aes256.c:144: printf("AES-256 Encryption (ECB) - test vector result:\nCiphertext: ");
	ld	hl, #___str_0
	push	hl
	call	_printf
	pop	af
	C$aes256.c$145$2_0$91	= .
	.globl	C$aes256.c$145$2_0$91
;/work/source_code/testingfiles/aes256.c:145: for (int i = 0; i < 16; ++i) printf("%02x ", ciphertext[i]);
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
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	add	hl, bc
	ld	e, (hl)
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_1
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
	inc	bc
	jp	00103$
00101$:
	C$aes256.c$146$1_0$90	= .
	.globl	C$aes256.c$146$1_0$90
;/work/source_code/testingfiles/aes256.c:146: printf("\n");
	ld	hl, #___str_3
	push	hl
	call	_puts
	pop	af
	C$aes256.c$149$1_0$90	= .
	.globl	C$aes256.c$149$1_0$90
;/work/source_code/testingfiles/aes256.c:149: return 0;
	ld	hl, #0x0000
00105$:
	C$aes256.c$150$1_0$90	= .
	.globl	C$aes256.c$150$1_0$90
;/work/source_code/testingfiles/aes256.c:150: }
	ld	sp, ix
	pop	ix
	C$aes256.c$150$1_0$90	= .
	.globl	C$aes256.c$150$1_0$90
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Faes256$__str_0$0_0$0 == .
___str_0:
	.ascii "AES-256 Encryption (ECB) - test vector result:"
	.db 0x0a
	.ascii "Ciphertext: "
	.db 0x00
Faes256$__str_1$0_0$0 == .
___str_1:
	.ascii "%02x "
	.db 0x00
Faes256$__str_3$0_0$0 == .
___str_3:
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
