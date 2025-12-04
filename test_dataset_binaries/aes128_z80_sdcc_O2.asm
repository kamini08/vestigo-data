;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module aes128
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _AES128_Encrypt
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
	Faes128$xt$0$0	= .
	.globl	Faes128$xt$0$0
	C$aes128.c$32$0_0$35	= .
	.globl	C$aes128.c$32$0_0$35
;/work/source_code/testingfiles/aes128.c:32: static uint8_t xt(uint8_t a) {
;	---------------------------------
; Function xt
; ---------------------------------
_xt:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes128.c$33$1_0$35	= .
	.globl	C$aes128.c$33$1_0$35
;/work/source_code/testingfiles/aes128.c:33: return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1B : 0));
	ld	a, 4 (ix)
	add	a, a
	ld	c, a
	ld	a, 4 (ix)
	rlca
	jr	NC,00103$
	ld	de, #0x001b
	jr	00104$
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
	C$aes128.c$34$1_0$35	= .
	.globl	C$aes128.c$34$1_0$35
;/work/source_code/testingfiles/aes128.c:34: }
	pop	ix
	C$aes128.c$34$1_0$35	= .
	.globl	C$aes128.c$34$1_0$35
	XFaes128$xt$0$0	= .
	.globl	XFaes128$xt$0$0
	ret
Faes128$SBOX$0_0$0 == .
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
Faes128$RCON$0_0$0 == .
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
	Faes128$SubBytes$0$0	= .
	.globl	Faes128$SubBytes$0$0
	C$aes128.c$36$1_0$38	= .
	.globl	C$aes128.c$36$1_0$38
;/work/source_code/testingfiles/aes128.c:36: static void SubBytes(uint8_t *state) {
;	---------------------------------
; Function SubBytes
; ---------------------------------
_SubBytes:
	push	ix
	ld	ix,#0
	add	ix,sp
	C$aes128.c$37$2_0$38	= .
	.globl	C$aes128.c$37$2_0$38
;/work/source_code/testingfiles/aes128.c:37: for(int i = 0; i < 16; i++)
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
	C$aes128.c$38$2_0$38	= .
	.globl	C$aes128.c$38$2_0$38
;/work/source_code/testingfiles/aes128.c:38: state[i] = SBOX[state[i]];
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
	C$aes128.c$37$2_0$38	= .
	.globl	C$aes128.c$37$2_0$38
;/work/source_code/testingfiles/aes128.c:37: for(int i = 0; i < 16; i++)
	inc	bc
	jr	00103$
00105$:
	C$aes128.c$39$2_0$38	= .
	.globl	C$aes128.c$39$2_0$38
;/work/source_code/testingfiles/aes128.c:39: }
	pop	ix
	C$aes128.c$39$2_0$38	= .
	.globl	C$aes128.c$39$2_0$38
	XFaes128$SubBytes$0$0	= .
	.globl	XFaes128$SubBytes$0$0
	ret
	Faes128$ShiftRows$0$0	= .
	.globl	Faes128$ShiftRows$0$0
	C$aes128.c$41$2_0$40	= .
	.globl	C$aes128.c$41$2_0$40
;/work/source_code/testingfiles/aes128.c:41: static void ShiftRows(uint8_t *s) {
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
	C$aes128.c$43$1_0$40	= .
	.globl	C$aes128.c$43$1_0$40
;/work/source_code/testingfiles/aes128.c:43: memcpy(t, s, 16);
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
	C$aes128.c$45$1_0$40	= .
	.globl	C$aes128.c$45$1_0$40
;/work/source_code/testingfiles/aes128.c:45: s[1]  = t[5];  s[5]  = t[9];  s[9]  = t[13]; s[13] = t[1];
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
	C$aes128.c$46$1_0$40	= .
	.globl	C$aes128.c$46$1_0$40
;/work/source_code/testingfiles/aes128.c:46: s[2]  = t[10]; s[10] = t[2];  s[6]  = t[14]; s[14] = t[6];
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
	C$aes128.c$47$1_0$40	= .
	.globl	C$aes128.c$47$1_0$40
;/work/source_code/testingfiles/aes128.c:47: s[3]  = t[15]; s[7]  = t[3];  s[11] = t[7];  s[15] = t[11];
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
	C$aes128.c$48$1_0$40	= .
	.globl	C$aes128.c$48$1_0$40
;/work/source_code/testingfiles/aes128.c:48: }
	ld	sp, ix
	pop	ix
	C$aes128.c$48$1_0$40	= .
	.globl	C$aes128.c$48$1_0$40
	XFaes128$ShiftRows$0$0	= .
	.globl	XFaes128$ShiftRows$0$0
	ret
	Faes128$MixColumns$0$0	= .
	.globl	Faes128$MixColumns$0$0
	C$aes128.c$50$1_0$43	= .
	.globl	C$aes128.c$50$1_0$43
;/work/source_code/testingfiles/aes128.c:50: static void MixColumns(uint8_t *s) {
;	---------------------------------
; Function MixColumns
; ---------------------------------
_MixColumns:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-11
	add	hl, sp
	ld	sp, hl
	C$aes128.c$51$2_0$43	= .
	.globl	C$aes128.c$51$2_0$43
;/work/source_code/testingfiles/aes128.c:51: for(int i=0;i<4;i++){
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00105$
	C$aes128.c$52$3_0$44	= .
	.globl	C$aes128.c$52$3_0$44
;/work/source_code/testingfiles/aes128.c:52: int a = i*4;
	ld	e, c
	ld	d, b
	sla	e
	rl	d
	sla	e
	rl	d
	C$aes128.c$53$3_0$44	= .
	.globl	C$aes128.c$53$3_0$44
;/work/source_code/testingfiles/aes128.c:53: uint8_t x0=s[a], x1=s[a+1], x2=s[a+2], x3=s[a+3];
	ld	a, 4 (ix)
	add	a, e
	ld	-11 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-10 (ix), a
	pop	hl
	push	hl
	ld	a, (hl)
	ld	-9 (ix), a
	ld	hl, #0x0001
	add	hl, de
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -2 (ix)
	add	a, 4 (ix)
	ld	-8 (ix), a
	ld	a, -1 (ix)
	adc	a, 5 (ix)
	ld	-7 (ix), a
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, (hl)
	ld	-6 (ix), a
	ld	hl, #0x0002
	add	hl, de
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -2 (ix)
	add	a, 4 (ix)
	ld	-5 (ix), a
	ld	a, -1 (ix)
	adc	a, 5 (ix)
	ld	-4 (ix), a
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	a, (hl)
	ld	-3 (ix), a
	inc	de
	inc	de
	inc	de
	ld	a, e
	add	a, 4 (ix)
	ld	-2 (ix), a
	ld	a, d
	adc	a, 5 (ix)
	ld	-1 (ix), a
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	e, (hl)
	C$aes128.c$55$3_0$44	= .
	.globl	C$aes128.c$55$3_0$44
;/work/source_code/testingfiles/aes128.c:55: s[a]   = xt(x0) ^ xt(x1) ^ x1 ^ x2 ^ x3;
	push	bc
	push	de
	ld	a, -9 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	pop	de
	pop	bc
	push	hl
	push	bc
	push	de
	ld	a, -6 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	pop	hl
	xor	a, l
	xor	a, -6 (ix)
	xor	a, -3 (ix)
	xor	a, e
	pop	hl
	push	hl
	ld	(hl), a
	C$aes128.c$56$3_0$44	= .
	.globl	C$aes128.c$56$3_0$44
;/work/source_code/testingfiles/aes128.c:56: s[a+1] = x0 ^ xt(x1) ^ xt(x2) ^ x2 ^ x3;
	push	bc
	push	de
	ld	a, -6 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -9 (ix)
	ld	d, a
	push	bc
	push	de
	ld	a, -3 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, d
	xor	a, -3 (ix)
	xor	a, e
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), a
	C$aes128.c$57$3_0$44	= .
	.globl	C$aes128.c$57$3_0$44
;/work/source_code/testingfiles/aes128.c:57: s[a+2] = x0 ^ x1 ^ xt(x2) ^ xt(x3) ^ x3;
	ld	a, -9 (ix)
	xor	a, -6 (ix)
	ld	d, a
	push	bc
	push	de
	ld	a, -3 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, d
	ld	d, a
	push	bc
	push	de
	ld	a, e
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, d
	xor	a, e
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	(hl), a
	C$aes128.c$58$3_0$44	= .
	.globl	C$aes128.c$58$3_0$44
;/work/source_code/testingfiles/aes128.c:58: s[a+3] = xt(x0) ^ x0 ^ x1 ^ x2 ^ xt(x3);
	push	bc
	push	de
	ld	a, -9 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -9 (ix)
	xor	a, -6 (ix)
	xor	a, -3 (ix)
	ld	l, a
	push	hl
	push	bc
	ld	a, e
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	bc
	pop	hl
	xor	a, l
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$aes128.c$51$2_0$43	= .
	.globl	C$aes128.c$51$2_0$43
;/work/source_code/testingfiles/aes128.c:51: for(int i=0;i<4;i++){
	inc	bc
	jp	00103$
00105$:
	C$aes128.c$60$2_0$43	= .
	.globl	C$aes128.c$60$2_0$43
;/work/source_code/testingfiles/aes128.c:60: }
	ld	sp, ix
	pop	ix
	C$aes128.c$60$2_0$43	= .
	.globl	C$aes128.c$60$2_0$43
	XFaes128$MixColumns$0$0	= .
	.globl	XFaes128$MixColumns$0$0
	ret
	Faes128$AddRoundKey$0$0	= .
	.globl	Faes128$AddRoundKey$0$0
	C$aes128.c$62$2_0$47	= .
	.globl	C$aes128.c$62$2_0$47
;/work/source_code/testingfiles/aes128.c:62: static void AddRoundKey(uint8_t *s, uint8_t rk[16]) {
;	---------------------------------
; Function AddRoundKey
; ---------------------------------
_AddRoundKey:
	push	ix
	ld	ix,#0
	add	ix,sp
	dec	sp
	C$aes128.c$63$2_0$47	= .
	.globl	C$aes128.c$63$2_0$47
;/work/source_code/testingfiles/aes128.c:63: for(int i=0;i<16;i++) s[i] ^= rk[i];
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
	jr	00103$
00105$:
	C$aes128.c$64$2_0$47	= .
	.globl	C$aes128.c$64$2_0$47
;/work/source_code/testingfiles/aes128.c:64: }
	inc	sp
	pop	ix
	C$aes128.c$64$2_0$47	= .
	.globl	C$aes128.c$64$2_0$47
	XFaes128$AddRoundKey$0$0	= .
	.globl	XFaes128$AddRoundKey$0$0
	ret
	Faes128$KeyExpansion$0$0	= .
	.globl	Faes128$KeyExpansion$0$0
	C$aes128.c$66$2_0$49	= .
	.globl	C$aes128.c$66$2_0$49
;/work/source_code/testingfiles/aes128.c:66: static void KeyExpansion(uint8_t key[16], uint8_t roundKeys[11][16]) {
;	---------------------------------
; Function KeyExpansion
; ---------------------------------
_KeyExpansion:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-9
	add	hl, sp
	ld	sp, hl
	C$aes128.c$67$1_0$49	= .
	.globl	C$aes128.c$67$1_0$49
;/work/source_code/testingfiles/aes128.c:67: memcpy(roundKeys[0], key, 16);
	ld	c, 6 (ix)
	ld	b, 7 (ix)
	ld	e, c
	ld	d, b
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	bc
	ld	bc, #0x0010
	ldir
	pop	bc
	C$aes128.c$69$3_0$51	= .
	.globl	C$aes128.c$69$3_0$51
;/work/source_code/testingfiles/aes128.c:69: for(int r=1;r<=10;r++){
	ld	de, #0x0001
00107$:
	ld	a, #0x0a
	cp	a, e
	ld	a, #0x00
	sbc	a, d
	jp	PO, 00133$
	xor	a, #0x80
00133$:
	jp	M, 00109$
	C$aes128.c$70$3_0$51	= .
	.globl	C$aes128.c$70$3_0$51
;/work/source_code/testingfiles/aes128.c:70: uint8_t *prev = roundKeys[r-1];
	ld	l, e
	ld	h, d
	dec	hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, bc
	inc	sp
	inc	sp
	push	hl
	C$aes128.c$71$3_0$51	= .
	.globl	C$aes128.c$71$3_0$51
;/work/source_code/testingfiles/aes128.c:71: uint8_t *curr = roundKeys[r];
	ld	l, e
	ld	h, d
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, bc
	ld	-7 (ix), l
	ld	-6 (ix), h
	C$aes128.c$73$3_0$51	= .
	.globl	C$aes128.c$73$3_0$51
;/work/source_code/testingfiles/aes128.c:73: curr[0] = prev[0] ^ SBOX[prev[13]] ^ RCON[r];
	pop	hl
	push	hl
	ld	a, (hl)
	ld	-1 (ix), a
	pop	hl
	push	hl
	push	bc
	ld	bc, #0x000d
	add	hl, bc
	pop	bc
	ld	a, (hl)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	-1 (ix), a
	ld	hl, #_RCON
	add	hl, de
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	ld	(hl), a
	C$aes128.c$74$3_0$51	= .
	.globl	C$aes128.c$74$3_0$51
;/work/source_code/testingfiles/aes128.c:74: curr[1] = prev[1] ^ SBOX[prev[14]];
	ld	a, -7 (ix)
	add	a, #0x01
	ld	-3 (ix), a
	ld	a, -6 (ix)
	adc	a, #0x00
	ld	-2 (ix), a
	pop	hl
	push	hl
	inc	hl
	ld	a, (hl)
	ld	-1 (ix), a
	pop	hl
	push	hl
	push	bc
	ld	bc, #0x000e
	add	hl, bc
	pop	bc
	ld	a, (hl)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	(hl), a
	C$aes128.c$75$3_0$51	= .
	.globl	C$aes128.c$75$3_0$51
;/work/source_code/testingfiles/aes128.c:75: curr[2] = prev[2] ^ SBOX[prev[15]];
	ld	a, -7 (ix)
	add	a, #0x02
	ld	-3 (ix), a
	ld	a, -6 (ix)
	adc	a, #0x00
	ld	-2 (ix), a
	pop	hl
	push	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	-1 (ix), a
	pop	hl
	push	hl
	push	bc
	ld	bc, #0x000f
	add	hl, bc
	pop	bc
	ld	a, (hl)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	(hl), a
	C$aes128.c$76$3_0$51	= .
	.globl	C$aes128.c$76$3_0$51
;/work/source_code/testingfiles/aes128.c:76: curr[3] = prev[3] ^ SBOX[prev[12]];
	ld	a, -7 (ix)
	add	a, #0x03
	ld	-3 (ix), a
	ld	a, -6 (ix)
	adc	a, #0x00
	ld	-2 (ix), a
	pop	hl
	push	hl
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	-1 (ix), a
	pop	hl
	push	hl
	push	bc
	ld	bc, #0x000c
	add	hl, bc
	pop	bc
	ld	a, (hl)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	(hl), a
	C$aes128.c$78$2_0$49	= .
	.globl	C$aes128.c$78$2_0$49
;/work/source_code/testingfiles/aes128.c:78: for(int i=4;i<16;i++)
	ld	-2 (ix), #0x04
	xor	a, a
	ld	-1 (ix), a
00104$:
	ld	a, -2 (ix)
	sub	a, #0x10
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00108$
	C$aes128.c$79$4_0$52	= .
	.globl	C$aes128.c$79$4_0$52
;/work/source_code/testingfiles/aes128.c:79: curr[i] = prev[i] ^ curr[i-4];
	ld	a, -7 (ix)
	add	a, -2 (ix)
	ld	-5 (ix), a
	ld	a, -6 (ix)
	adc	a, -1 (ix)
	ld	-4 (ix), a
	ld	a, -9 (ix)
	add	a, -2 (ix)
	ld	l, a
	ld	a, -8 (ix)
	adc	a, -1 (ix)
	ld	h, a
	ld	a, (hl)
	ld	-3 (ix), a
	ld	a, -2 (ix)
	add	a, #0xfc
	ld	l, a
	ld	a, -1 (ix)
	adc	a, #0xff
	ld	h, a
	ld	a, l
	add	a, -7 (ix)
	ld	l, a
	ld	a, h
	adc	a, -6 (ix)
	ld	h, a
	ld	a, (hl)
	xor	a, -3 (ix)
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	(hl), a
	C$aes128.c$78$4_0$52	= .
	.globl	C$aes128.c$78$4_0$52
;/work/source_code/testingfiles/aes128.c:78: for(int i=4;i<16;i++)
	inc	-2 (ix)
	jr	NZ,00104$
	inc	-1 (ix)
	jr	00104$
00108$:
	C$aes128.c$69$2_0$50	= .
	.globl	C$aes128.c$69$2_0$50
;/work/source_code/testingfiles/aes128.c:69: for(int r=1;r<=10;r++){
	inc	de
	jp	00107$
00109$:
	C$aes128.c$81$2_0$49	= .
	.globl	C$aes128.c$81$2_0$49
;/work/source_code/testingfiles/aes128.c:81: }
	ld	sp, ix
	pop	ix
	C$aes128.c$81$2_0$49	= .
	.globl	C$aes128.c$81$2_0$49
	XFaes128$KeyExpansion$0$0	= .
	.globl	XFaes128$KeyExpansion$0$0
	ret
	G$AES128_Encrypt$0$0	= .
	.globl	G$AES128_Encrypt$0$0
	C$aes128.c$83$2_0$54	= .
	.globl	C$aes128.c$83$2_0$54
;/work/source_code/testingfiles/aes128.c:83: void AES128_Encrypt(uint8_t *in, uint8_t *out, uint8_t key[16]) {
;	---------------------------------
; Function AES128_Encrypt
; ---------------------------------
_AES128_Encrypt::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-204
	add	hl, sp
	ld	sp, hl
	C$aes128.c$87$1_0$54	= .
	.globl	C$aes128.c$87$1_0$54
;/work/source_code/testingfiles/aes128.c:87: memcpy(state, in, 16);
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
	C$aes128.c$88$1_0$54	= .
	.globl	C$aes128.c$88$1_0$54
;/work/source_code/testingfiles/aes128.c:88: KeyExpansion(key, rk);
	ld	hl, #16
	add	hl, sp
	push	bc
	push	hl
	ld	l, 8 (ix)
	ld	h, 9 (ix)
	push	hl
	call	_KeyExpansion
	pop	af
	pop	af
	pop	bc
	C$aes128.c$90$1_0$54	= .
	.globl	C$aes128.c$90$1_0$54
;/work/source_code/testingfiles/aes128.c:90: AddRoundKey(state, rk[0]);
	ld	hl, #16
	add	hl, sp
	ld	e, c
	ld	d, b
	push	bc
	push	hl
	push	de
	call	_AddRoundKey
	pop	af
	pop	af
	pop	bc
	C$aes128.c$92$3_0$56	= .
	.globl	C$aes128.c$92$3_0$56
;/work/source_code/testingfiles/aes128.c:92: for(int round=1; round<Nr; round++){
	ld	-12 (ix), c
	ld	-11 (ix), b
	ld	-10 (ix), c
	ld	-9 (ix), b
	ld	-8 (ix), c
	ld	-7 (ix), b
	ld	hl, #16
	add	hl, sp
	ld	-6 (ix), l
	ld	-5 (ix), h
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	-2 (ix), #0x01
	xor	a, a
	ld	-1 (ix), a
00103$:
	ld	a, -2 (ix)
	sub	a, #0x0a
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$aes128.c$93$3_0$56	= .
	.globl	C$aes128.c$93$3_0$56
;/work/source_code/testingfiles/aes128.c:93: SubBytes(state);
	ld	e, -12 (ix)
	ld	d, -11 (ix)
	push	bc
	push	de
	call	_SubBytes
	pop	af
	pop	bc
	C$aes128.c$94$3_0$56	= .
	.globl	C$aes128.c$94$3_0$56
;/work/source_code/testingfiles/aes128.c:94: ShiftRows(state);
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	push	bc
	push	de
	call	_ShiftRows
	pop	af
	pop	bc
	C$aes128.c$95$3_0$56	= .
	.globl	C$aes128.c$95$3_0$56
;/work/source_code/testingfiles/aes128.c:95: MixColumns(state);
	ld	e, -8 (ix)
	ld	d, -7 (ix)
	push	bc
	push	de
	call	_MixColumns
	pop	af
	pop	bc
	C$aes128.c$96$3_0$56	= .
	.globl	C$aes128.c$96$3_0$56
;/work/source_code/testingfiles/aes128.c:96: AddRoundKey(state, rk[round]);
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
	add	a, -6 (ix)
	ld	e, a
	ld	a, d
	adc	a, -5 (ix)
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
	C$aes128.c$92$2_0$55	= .
	.globl	C$aes128.c$92$2_0$55
;/work/source_code/testingfiles/aes128.c:92: for(int round=1; round<Nr; round++){
	inc	-2 (ix)
	jr	NZ,00103$
	inc	-1 (ix)
	jr	00103$
00101$:
	C$aes128.c$99$1_0$54	= .
	.globl	C$aes128.c$99$1_0$54
;/work/source_code/testingfiles/aes128.c:99: SubBytes(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_SubBytes
	pop	af
	pop	bc
	C$aes128.c$100$1_0$54	= .
	.globl	C$aes128.c$100$1_0$54
;/work/source_code/testingfiles/aes128.c:100: ShiftRows(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_ShiftRows
	pop	af
	pop	bc
	C$aes128.c$101$1_0$54	= .
	.globl	C$aes128.c$101$1_0$54
;/work/source_code/testingfiles/aes128.c:101: AddRoundKey(state, rk[Nr]);
	ld	a, -6 (ix)
	add	a, #0xa0
	ld	e, a
	ld	a, -5 (ix)
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
	C$aes128.c$103$1_0$54	= .
	.globl	C$aes128.c$103$1_0$54
;/work/source_code/testingfiles/aes128.c:103: memcpy(out, state, 16);
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	l, c
	ld	h, b
	ld	bc, #0x0010
	ldir
	C$aes128.c$104$1_0$54	= .
	.globl	C$aes128.c$104$1_0$54
;/work/source_code/testingfiles/aes128.c:104: }
	ld	sp, ix
	pop	ix
	C$aes128.c$104$1_0$54	= .
	.globl	C$aes128.c$104$1_0$54
	XG$AES128_Encrypt$0$0	= .
	.globl	XG$AES128_Encrypt$0$0
	ret
	G$main$0$0	= .
	.globl	G$main$0$0
	C$aes128.c$106$1_0$57	= .
	.globl	C$aes128.c$106$1_0$57
;/work/source_code/testingfiles/aes128.c:106: int main() {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-50
	add	hl, sp
	ld	sp, hl
	C$aes128.c$107$2_0$57	= .
	.globl	C$aes128.c$107$2_0$57
;/work/source_code/testingfiles/aes128.c:107: uint8_t key[16] = {
	ld	hl, #0
	add	hl, sp
	ex	de, hl
	ld	a, #0x2b
	ld	(de), a
	ld	l, e
	ld	h, d
	inc	hl
	ld	(hl), #0x7e
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	ld	(hl), #0x15
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0x16
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0x28
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0xae
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0xd2
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0xa6
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0xab
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0xf7
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0x15
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0x88
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0x09
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0xcf
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x4f
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0x3c
	C$aes128.c$112$2_0$57	= .
	.globl	C$aes128.c$112$2_0$57
;/work/source_code/testingfiles/aes128.c:112: uint8_t plaintext[16] = {
	ld	hl, #16
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
	C$aes128.c$119$1_0$57	= .
	.globl	C$aes128.c$119$1_0$57
;/work/source_code/testingfiles/aes128.c:119: AES128_Encrypt(plaintext, ciphertext, key);
	ld	hl, #32
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	push	de
	push	hl
	push	bc
	call	_AES128_Encrypt
	ld	hl, #6
	add	hl, sp
	ld	sp, hl
	C$aes128.c$121$1_0$57	= .
	.globl	C$aes128.c$121$1_0$57
;/work/source_code/testingfiles/aes128.c:121: printf("AES-128 Alt Implementation\nCiphertext: ");
	ld	hl, #___str_0
	push	hl
	call	_printf
	pop	af
	C$aes128.c$122$2_0$58	= .
	.globl	C$aes128.c$122$2_0$58
;/work/source_code/testingfiles/aes128.c:122: for(int i=0;i<16;i++) printf("%02x ", ciphertext[i]);
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
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
	jr	00103$
00101$:
	C$aes128.c$123$1_0$57	= .
	.globl	C$aes128.c$123$1_0$57
;/work/source_code/testingfiles/aes128.c:123: printf("\n");
	ld	hl, #___str_3
	push	hl
	call	_puts
	pop	af
	C$aes128.c$125$1_0$57	= .
	.globl	C$aes128.c$125$1_0$57
;/work/source_code/testingfiles/aes128.c:125: return 0;
	ld	hl, #0x0000
	C$aes128.c$126$1_0$57	= .
	.globl	C$aes128.c$126$1_0$57
;/work/source_code/testingfiles/aes128.c:126: }
	ld	sp, ix
	pop	ix
	C$aes128.c$126$1_0$57	= .
	.globl	C$aes128.c$126$1_0$57
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Faes128$__str_0$0_0$0 == .
___str_0:
	.ascii "AES-128 Alt Implementation"
	.db 0x0a
	.ascii "Ciphertext: "
	.db 0x00
Faes128$__str_1$0_0$0 == .
___str_1:
	.ascii "%02x "
	.db 0x00
Faes128$__str_3$0_0$0 == .
___str_3:
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
