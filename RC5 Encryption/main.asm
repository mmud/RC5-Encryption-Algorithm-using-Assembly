;Mahmoud Shaban Amer (ndpro)
;RC5 Encryption Project

.include "m328Pdef.inc"

; Define Variables:
.EQU PL = 0xe1 
.EQU PH = 0xb7
.EQU QL = 0x37
.EQU QH = 0x9e
.EQU R = 8    
.EQU T = 18   
.EQU W = 16   
.EQU U = 2    
.EQU B = 12   
.EQU C = 6    
.EQU N = 54   
; Memory locations for K[i]
.EQU BY0 = 0x0200
.EQU BY1 = 0x0201
.EQU BY2 = 0x0202
.EQU BY3 = 0x0203
.EQU BY4 = 0x0204
.EQU BY5 = 0x0205
.EQU BY6 = 0x0206
.EQU BY7 = 0x0207
.EQU BY8 = 0x0208
.EQU BY9 = 0x0209
.EQU BY10 = 0x020A
.EQU BY11 = 0x020B

; MACROs
.MACRO INPUT
    .DEF AH = R17
    ldi AH, high(@0)   
    .DEF AL = R16
    ldi AL, low(@0)    
    .DEF BH = R19
    ldi BH, high(@1)   
    .DEF BL = R18
    ldi BL, low(@1)    
.ENDMACRO
.MACRO SECRET_KEY
        LDI R20, @11
        STS BY0, R20
        LDI R20, @10
        STS BY1, R20
        LDI R20, @9
        STS BY2, R20
        LDI R20, @8
        STS BY3, R20
        LDI R20, @7
        STS BY4, R20
        LDI R20, @6
        STS BY5, R20
        LDI R20, @5
        STS BY6, R20
        LDI R20, @4
        STS BY7, R20
        LDI R20, @3
        STS BY8, R20
        LDI R20, @2
        STS BY9, R20
        LDI R20, @1
        STS BY10, R20
        LDI R20, @0
        STS BY11, R20
.ENDMACRO
.MACRO ROTL_WORD
        TST @2
        BREQ ZEROL
        MOV R25, @2         
    ROTL:
        ROL @1
        BST @0, 7
        ROL @0
        BLD @1, 0
        DEC R25
        BRNE ROTL
    ZEROL:
        nop
.ENDMACRO
.MACRO ROTR_WORD
        TST @2
        BREQ ZEROR
        MOV R25, @2          
    ROTR:
        ROR @0
        BST @1, 0
        ROR @1
        BLD @0, 7
        DEC R25
        BRNE ROTR
    ZEROR:
        nop
.ENDMACRO
.MACRO XOR_WORD            
        EOR @1, @3
        EOR @0, @2
.ENDMACRO
.MACRO SUB_WORD             
        SUB @1, @3
        SBC @0, @2
.ENDMACRO
.MACRO ADD_WORD            
        ADD @1, @3
        ADC @0, @2
.ENDMACRO

;==============================================================================
;*RC5_SETUP**********************************
;==============================================================================

.MACRO RC5_SETUP

		;----------------------------------------------------------------
        ; ----- Convert secret key (K[i]) to 6 words (L[i]) -------------
		;----------------------------------------------------------------

       
        ; Build L5:
        lds  r0, BY11
        lds  r1, BY10
        sts  0x022A, r1     
        sts  0x022B, r0 
        ; Build L4:
        lds  r0, BY9
        lds  r1, BY8
        sts  0x0228, r1
        sts  0x0229, r0
        ; Build L3:
        lds  r0, BY7
        lds  r1, BY6
        sts  0x0226, r1
        sts  0x0227, r0
        ; Build L2:
        lds  r0, BY5
        lds  r1, BY4
        sts  0x0224, r1
        sts  0x0225, r0
        ; Build L1:
        lds  r0, BY3
        lds  r1, BY2
        sts  0x0222, r1
        sts  0x0223, r0
        ; Build L0:
        lds  r0, BY1
        lds  r1, BY0
        sts  0x0220, r1
        sts  0x0221, r0
		;----------------------------------------------------
        ; ----- Step 2: Initialize expanded key table S[i] -----
		;----------------------------------------------------
        .EQU S0L = 0x0210
        .EQU S0H = 0x0211
        .EQU S1L = 0x0212
        .EQU S1H = 0x0213

        ldi ZL, low(S0L)
        ldi ZH, high(S0L)

        ldi R21, PL
        ldi R22, PH
        STS S0L, R21
        STS S0H, R22

        ldi R21, QL
        ldi R22, QH
        ldi R20, T
        subi R20, 1
    LOOP_S:
        LD R23, Z+          ; get low byte from current S[i]
        LD R24, Z+          ; get high byte from current S[i]
        ADD_WORD R24, R23, R22, R21   ; S[i] + Qw
        ST Z, R23           ; store result low byte
        STD Z+1, R24        ; store result high byte
        DEC R20
        BRNE LOOP_S
		;------------------------------------------------------
        ; ----- Step 3: Key Expansion (mixing in L array) -----
		;------------------------------------------------------
        clr R0
        clr R1
        clr R2
        clr R3
        ldi ZL, low(S0L)
        ldi ZH, high(S0L)
        ldi YL, low(0x0220)   
        ldi YH, high(0x0220)
        ldi R20, N
    LOOP_MIX:
        ADD_WORD R1, R0, R3, R2
        LD R23, Z
        LDD R24, Z+1
        ADD_WORD R1, R0, R24, R23
        ldi R22, 3
        ROTL_WORD R1, R0, R22
        ST Z, R0
        STD Z+1, R1
        ADD_WORD R3, R2, R1, R0
        mov R22, R2
        andi R22, 0x0F
        LD R23, Y
        LDD R24, Y+1
        ADD_WORD R3, R2, R24, R23
        ROTL_WORD R3, R2, R22
        ST Y, R2
        STD Y+1, R3
        RCALL I_RESET
        RCALL J_RESET
        DEC R20
        BRNE LOOP_MIX
.ENDMACRO

;==============================================================================
;RC5_ENCRYPT*********************************
;==============================================================================

.MACRO RC5_ENCRYPT
        LDI XL, 0x14
        LDI XH, 0x02
        LDS R22, S0L
        LDS R21, S0H
        ADD_WORD AH, AL, R21, R22
        LDS R22, S1L
        LDS R21, S1H
        ADD_WORD BH, BL, R21, R22
        LDI R20, R
    LOOP_E:
        LDI R22, 0x0F
        AND R22, BL  ;%16
        LD R23, X+
        LD R24, X+
        XOR_WORD AH, AL, BH, BL
        ROTL_WORD AH, AL, R22
        ADD_WORD AH, AL, R24, R23
        LDI R22, 0x0F
        AND R22, AL  ;%16
        LD R23, X+
        LD R24, X+
        XOR_WORD BH, BL, AH, AL
        ROTL_WORD BH, BL, R22
        ADD_WORD BH, BL, R24, R23
        DEC R20
        BRNE LOOP_E
.ENDMACRO

;==============================================================================
;*RC5_DECRYPT**********************************
;==============================================================================

.MACRO RC5_DECRYPT
        LDI XL, 0x34
        LDI XH, 0x02
        LDI R20, 8
    LOOP_D:
        LDI R22, 0x0F
        AND R22, AL
        LD R23, -X
        LD R24, -X
        SUB_WORD BH, BL, R23, R24
        ROTR_WORD BH, BL, R22
        XOR_WORD BH, BL, AH, AL
        LDI R22, 0x0F
        AND R22, BL
        LD R23, -X
        LD R24, -X
        SUB_WORD AH, AL, R23, R24
        ROTR_WORD AH, AL, R22
        XOR_WORD AH, AL, BH, BL
        DEC R20
        BRNE LOOP_D
        LDS R22, S0H
        LDS R21, S0L
        SUB_WORD AH, AL, R22, R21
        LDS R22, S1H
        LDS R21, S1L
        SUB_WORD BH, BL, R22, R21
.ENDMACRO



;==============================================================================
;*LCD_Writer***********************************
;==============================================================================



.MACRO LCD

;================================================================
LCD_write_2:
      LDI   R25, 0xFF
      OUT   DDRD, R25         ;set port D o/p for data
      OUT   DDRB, R25         ;set port B o/p for command
      CBI   PORTB, 0          ;EN = 0
      RCALL delay_ms_2        ;wait for LCD power on
      ;-----------------------------------------------------
      RCALL LCD_init_2        ;subroutine to initialize LCD
      ;-----------------------------------------------------
      RCALL disp_message_2    ;subroutine to display message (only once)
      
      ; End of program - infinite loop to stop execution
end_2:  RJMP  end_dis
;================================================================
LCD_init_2:
      LDI   R25, 0x33         ;init LCD for 4-bit data
      RCALL command_wrt_2       
      RCALL delay_ms_2
      LDI   R25, 0x32         
      RCALL command_wrt_2
      RCALL delay_ms_2
      LDI   R25, 0x28         ;LCD 2 lines, 5x7 matrix
      RCALL command_wrt_2
      RCALL delay_ms_2
      LDI   R25, 0x0C         ;disp ON, cursor OFF
      RCALL command_wrt_2
      LDI   R25, 0x01         ;clear LCD
      RCALL command_wrt_2
      RCALL delay_ms_2
      LDI   R25, 0x06         ;shift cursor right
      RCALL command_wrt_2
      RET  
;================================================================
command_wrt_2:
      MOV   R30, R25          ;use R30 instead of R27
      ANDI  R30, 0xF0         ;mask low nibble & keep high nibble
      OUT   PORTD, R30        ;o/p high nibble to port D
      CBI   PORTB, 1          ;RS = 0 for command
      SBI   PORTB, 0          ;EN = 1
      RCALL delay_short_2       
      CBI   PORTB, 0          ;EN = 0
      RCALL delay_us_2          
      ;----------------------------------------------------
      MOV   R30, R25          
      SWAP  R30               ;swap nibbles
      ANDI  R30, 0xF0         
      OUT   PORTD, R30        
      SBI   PORTB, 0          
      RCALL delay_short_2       
      CBI   PORTB, 0          
      RCALL delay_us_2          
      RET
;================================================================
data_wrt_2:
      MOV   R30, R25          ;use R30 instead of R27
      ANDI  R30, 0xF0         
      OUT   PORTD, R30        
      SBI   PORTB, 1          ;RS = 1 for data
      SBI   PORTB, 0          ;EN = 1
      RCALL delay_short_2       
      CBI   PORTB, 0          
      RCALL delay_us_2          
      ;----------------------------------------------------
      MOV   R30, R25          
      SWAP  R30               
      ANDI  R30, 0xF0         
      OUT   PORTD, R30        
      SBI   PORTB, 0          
      RCALL delay_short_2       
      CBI   PORTB, 0          
      RCALL delay_us_2          
      RET
;================================================================
disp_message_2:
      MOV   R25, R17          ;display characters via R25
      RCALL data_wrt_2          
      RCALL delay_seconds_2	  
	  MOV   R25, R16          ;display characters via R25
      RCALL data_wrt_2          
      RCALL delay_seconds_2  
	  MOV   R25, R19          ;display characters via R25
      RCALL data_wrt_2          
      RCALL delay_seconds_2
	  MOV   R25, R18          ;display characters via R25
      RCALL data_wrt_2          
      RCALL delay_seconds_2     
      ;----------------
      LDI   R28, 12           ;wait 3 seconds (using R28)
l2_2:   RCALL delay_seconds_2
      DEC   R28
      BRNE  l2_2
      RET
;================================================================
delay_short_2:
      NOP
      NOP
      RET
;------------------------
delay_us_2:
      LDI   R20, 90           ;allowed register
l3_2:   RCALL delay_short_2
      DEC   R20
      BRNE  l3_2
      RET
;-----------------------
delay_ms_2:
      LDI   R29, 40           ;using R29
l4_2:   RCALL delay_us_2
      DEC   R29
      BRNE  l4_2
      RET
;================================================================
delay_seconds_2:        
    LDI   R20, 255            ;outer loop (allowed)
l5_2: LDI   R29, 255            ;mid loop (R29)
l6_2: LDI   R30, 20             ;inner loop (R30)
l7_2: DEC   R30         
    BRNE  l7_2          
    DEC   R29         
    BRNE  l6_2          
    DEC   R20         
    BRNE  l5_2          
    RET               
;----------------------------------------------------------------
end_dis:
nop
.ENDMACRO



;=======================================================================
;*TEST**********************************
;=======================================================================

start:
	ldi r20, high(RAMEND)
	out SPH, r20
	ldi r20, low(RAMEND)
	out SPL, r20

    SECRET_KEY 0x4D,0x61,0x68,0x6D,0x6F,0x75,0x64,0x53,0x68,0x61,0x62,0x6E
    RC5_SETUP

	; Test case: "NDPR" as 0x4E44 and 0x5052
	INPUT 0x4E44, 0x5052
	LCD

	RC5_ENCRYPT
	LCD

	RC5_DECRYPT
	LCD

; Test case: "MASS" as 0x4D41 and 0x5353
	INPUT 0x4D41, 0x5353
	LCD

	RC5_ENCRYPT
	LCD

	RC5_DECRYPT
	LCD

end_f: 
	 RJMP  end_f

	 I_RESET:
        inc ZL
        inc ZL
        ldi R21, 0x34
        cpse ZL, R21
        ret    
        ldi ZL, low(S0L)
        ret


J_RESET:
        inc YL
        inc YL
        ldi R21, 0x0C
        cpse YL, R21
        ret
        LDI YL, low(0x0220)   ; reset Y pointer to start of L-array
        ret