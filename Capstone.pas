{
  Pascal language binding for the Capstone engine <http://www.capstone-engine.org/>

  Copyright (C) 2018, Max
}

unit Capstone;

interface

uses
  SysUtils,Winapi.Windows,Classes, CapstoneApi, CapstoneX86,
  Collections.LinkedList;

const
 MAX_DISASM_BUFFER = 16;
 CP_MODE_32        = 32;
 CP_MODE_64        = 64;

type
  Mnemonics = Integer;
  TBuffDis  = array[0..MAX_DISASM_BUFFER - 1] of UInt8 ;

  TRef  = record
    RefFrom : UInt64;
    idxRefTo: Integer;
  end;

  TCpuOperandTipo = (TIPO_INVALID=0,
                  T_REG,
                  T_IMM,
                  T_MEM,
                  T_OPERAND,
                  VM_REGISTRO = $10,
                  VM_MEMORIA  = $20,
                  VM_COSTANTE = $30);

  TRegisters =( REG_INVALID = 0,
                AH, AL, AX, BH, BL,
                BP, BPL, BX, CH, CL,
                rCS, CX, DH, DI, DIL,
                DL, rDS, DX, EAX, EBP,
                EBX, ECX, EDI, EDX, EFLAGS,
                EIP, EIZ, rES, ESI, ESP,
                FPSW, rFS, rGS, IP, RAX,
                RBP, RBX, RCX, RDI, RDX,
                RIP, RIZ, RSI, RSP, SI,
                SIL, SP, SPL, rSS, CR0,
                CR1, CR2, CR3, CR4, CR5,
                CR6, CR7, CR8, CR9, CR10,
                CR11, CR12, CR13, CR14, CR15,
                DR0, DR1, DR2, DR3, DR4,
                DR5, DR6, DR7, DR8, DR9,
                DR10, DR11, DR12, DR13, DR14,
                DR15, FP0, FP1, FP2, FP3,
                FP4, FP5, FP6, FP7,
                K0, K1, K2, K3, K4,
                K5, K6, K7, MM0, MM1,
                MM2, MM3, MM4, MM5, MM6,
                MM7, R8, R9, R10, R11,
                R12, R13, R14, R15,
                ST0, ST1, ST2, ST3,
                ST4, ST5, ST6, ST7,
                XMM0, XMM1, XMM2, XMM3, XMM4,
                XMM5, XMM6, XMM7, XMM8, XMM9,
                XMM10, XMM11, XMM12, XMM13, XMM14,
                XMM15, XMM16, XMM17, XMM18, XMM19,
                XMM20, XMM21, XMM22, XMM23, XMM24,
                XMM25, XMM26, XMM27, XMM28, XMM29,
                XMM30, XMM31, YMM0, YMM1, YMM2,
                YMM3, YMM4, YMM5, YMM6, YMM7,
                YMM8, YMM9, YMM10, YMM11, YMM12,
                YMM13, YMM14, YMM15, YMM16, YMM17,
                YMM18, YMM19, YMM20, YMM21, YMM22,
                YMM23, YMM24, YMM25, YMM26, YMM27,
                YMM28, YMM29, YMM30, YMM31, ZMM0,
                ZMM1, ZMM2, ZMM3, ZMM4, ZMM5,
                ZMM6, ZMM7, ZMM8, ZMM9, ZMM10,
                ZMM11, ZMM12, ZMM13, ZMM14, ZMM15,
                ZMM16, ZMM17, ZMM18, ZMM19, ZMM20,
                ZMM21, ZMM22, ZMM23, ZMM24, ZMM25,
                ZMM26, ZMM27, ZMM28, ZMM29, ZMM30,
                ZMM31, R8B, R9B, R10B, R11B,
                R12B, R13B, R14B, R15B, R8D,
                R9D, R10D, R11D, R12D, R13D,
                R14D, R15D, R8W, R9W, R10W,
                R11W, R12W, R13W, R14W, R15W,
                ENDING);

  TSegments = ( INVALID=0,
                CS,
                SS,
                DS,
                ES,
                FS,
                GS ) ;

  TCpuOpCode = record
    mnem   : Mnemonics;

    Function ToString: string;
    class operator Implicit(mCmd   : Mnemonics):TCpuOpCode;
    class operator Implicit(ins    : x86_insn):TCpuOpCode;
    class operator Equal(Op1,Op2 : TCpuOpCode): Boolean; overload;
    class operator Equal(Op1 : TCpuOpCode;Op2 : Mnemonics): Boolean;overload;
    class operator NotEqual(Op1,Op2 : TCpuOpCode): Boolean; overload;
    class operator NotEqual(Op1:TCpuOpCode; OpCode: Mnemonics): Boolean; overload ;
  end;

  TCpuImm = record
    function ToString: string;
    class operator Implicit(pValue: Int64): TCpuImm;
    class operator Implicit(value: TCpuImm): Int64 ;
    class operator Implicit(value: TCpuImm): UInt64 ;
    class operator NotEqual(imm1, imm2: TCpuImm): Boolean;
    class operator NotEqual(imm1:TCpuImm; imm2 : UInt64): Boolean; overload;
    class operator NotEqual(imm1:TCpuImm; imm2 : Int64): Boolean;overload;
    class operator Equal(imm1,imm2 : TCpuImm): Boolean;
    class operator Equal(imm1:TCpuImm; imm2 : UInt64): Boolean; overload;
    class operator Equal(imm1:TCpuImm; imm2 : Int64): Boolean;overload;
    case Integer of
      0: ( U: UInt64 );
      1: ( S: Int64 );
  end;

  TCpuSeg = record
    seg    : TSegments;

    function ToString: string;
    class operator Implicit(pSeg: TSegments): TCpuSeg;
    class operator Equal(seg1,seg2 : TCpuSeg): Boolean;
  end;

  TCpuReg = record
   private
     function  GetSize: Integer;
     function  GetOffSet: Integer;
     function  GetParent: Integer;
     procedure SetSize(const Value: Integer);
     procedure SetParent(const Value: Integer);
   public
     reg    : TRegisters;

     class function FromString(sReg:string): TRegisters; static;
     function ToString: string;  overload;
     function ToString(vReg: TRegisters ): string; overload;
     class operator Implicit(pReg: x86_reg): TCpuReg;
     class operator Implicit(pReg: TRegisters): TCpuReg;
     class operator Explicit(pReg: TCpuReg): UInt8;
     class operator Equal(reg1,reg2 : TCpuReg): Boolean;overload;
     class operator Equal(reg1:TCpuReg; reg2: TRegisters): Boolean; overload;
     class operator NotEqual(reg1,reg2 : TCpuReg): Boolean;
     class operator LessThanOrEqual(reg1,reg2: TCpuReg) : Boolean;
     class operator GreaterThanOrEqual(reg1,reg2: TCpuReg) : Boolean;

     function ToReg(regParent: Integer; rSize: Byte): TRegisters;

     property Size  : Integer read GetSize   write SetSize;
     property Parent: Integer read GetParent write SetParent;
     property Offset: Integer read GetOffSet;
  end;

  TCpuMem = record
    seg    : TCpuSeg;
    base   : TCpuReg;
    index  : TCpuReg;
    scale  : TCpuImm;
    disp   : TCpuImm;

    function ToString: string;
    function Assigned: Boolean;
    class operator Equal(mem1,mem2 : TCpuMem): Boolean;
  end;

  TCpuOperand = record
    Tipo   : TCpuOperandTipo;
    reg    : TCpuReg;
    imm    : TCpuImm;
    mem    : TCpuMem;
    Size   : TCpuImm;
    Access : UInt8;

    function ToString: string;
    class operator Equal(op1,op2 : TCpuOperand): Boolean;
    class operator Explicit(pRegs : TRegisters): TCpuOperand;
    class operator Explicit(pReg  : TCpuReg): TCpuOperand;
    class operator Explicit(pValue: TCpuImm): TCpuOperand;
    class operator Explicit(pMem  : TCpuMem): TCpuOperand;
  end;

  PCpuIstruz = ^TCpuIstruz;
  TCpuIstruz = record
    opcode       : TCpuOpCode;
    opCount      : Integer;
    operands     : array[0..3] of TCpuOperand; // compatibile con capstone

    regs_read    : TArray<TCpuReg>;
    regs_written : TArray<TCpuReg>;
    groups       : TArray<UInt8>;
    prefix       : array[0..3] of UInt8;
    address      : UInt64 ;
    size         : UInt16;
    bytes        : array[0..MAX_DISASM_BUFFER - 1] of UInt8;
    eflags       : UInt64;
    {$IFDEF DEBUG} Istr_Str : string; {$ENDIF}

    refFrom      : TArray<TRef>;
    refTo        : UInt64;

    function IsEq(cCmd : TCpuOpCode; opTipo : TArray<TCpuOperandTipo>):Boolean;
    function ToString(PrintAddr: Boolean= False): string;
  end;
  TListCpuIstruz = array of TCpuIstruz;

  TTLabel = record
    Addr   : UInt64;
    sLabel : string;
  end;
  TLabelList = array of TTLabel;

  TCapstone = class
  private
    FNT          : Pointer;
    FMpFile      : PByte;
    FhFile       : THandle;
    FoFile       : THandle;
    FOpened      : Boolean;
    FHandle      : csh;
    FInitialized : Boolean;
    FSuccess     : Boolean;
    FMode        : cs_mode;
    FInsn        : Pcs_insn;
    FIstruz      : TCpuIstruz;
    FNomeFile    : AnsiString;
    function    InGroup(Istruz: TCpuIstruz;group: cs_group_type): Boolean; overload;
    function    InGroup(group: cs_group_type): Boolean; overload;
    function    FileOffsetToRva(dwFileOffset: UInt64): UInt64;
    function    RvaToOffset(Rva: UInt64): UInt64;
    function    VaToFileOffset(dwVA: UInt64): UInt64;
    procedure   SetNomeFile(const Value: AnsiString);
    procedure   OpenDisFile(const AFile: AnsiString);
    function    ReadMemory(const hProcess : THandle; const address: UInt64; Size: DWORD; var Buf : TBuffDis): Boolean;
    procedure   CloseDisFile;
    function    GetAddr: UInt64;
    function    GetMnm: string; overload;
    function    GetId: Cardinal;
    function    GetSize: Word;
    procedure   GetRegRW(ins: Pcs_insn);
    function    Internal_Ingroup(Istruz: TCpuIstruz; group: cs_group_type): Boolean;

  public
    // init function
    constructor Create;
    destructor  Destroy; override;
    function    Open: cs_err;
    procedure   Close;
    // disasm function
    Function    DisAssembleVA(VA_Addr: UInt64): Boolean;
    function    DisAsmBlock(addr : UInt64; data: PByte; size: NativeUInt; out AInsn: TListCpuIstruz): NativeUInt;
    function    DisAsmBuffer(addr: UInt64; data: PByte; out AInsn: TCpuIstruz): NativeUInt;
    procedure   Disassemble(const hProc: THandle; VA_Addr: UInt64);overload;
    procedure   Disassemble(FileOffset: UInt64);overload ;
    function    Disassemble(addr : UInt64; const data: array of byte): Boolean;overload;
    function    Disassemble(addr : UInt64; data: Pointer; size: NativeUInt): Boolean;overload;
    // porting from x64dbg
    function    DisasmBack(ip: UInt64; n: Word): UInt64;
    function    ResolveOpValue(opindex: Integer): Uint64;
    // utility function
    function    RegName(Reg: TRegisters): string;
    function    GetMnm(OpCode: Integer): string; overload;
    function    MemSizeName(size: Integer): string;
    function    FromCapstone(const insn: cs_insn): TCpuIstruz;
    function    FileOffsetToVa(dwFileOffset: UInt64): UInt64;
    function    IsCFI: Boolean; overload;
    function    IsCFI(Istruz: TCpuIstruz): Boolean;  overload;
    function    IsRet: Boolean; overload;
    function    IsRet(Istruz: TCpuIstruz): Boolean; overload;
    function    IsCall: Boolean; overload;
    function    IsCall(Istruz: TCpuIstruz): Boolean; overload;
    function    IsJmp: Boolean; overload;
    function    IsJmp(Istruz: TCpuIstruz): Boolean;overload;
    function    IsJcc: Boolean; overload;
    function    IsJcc(Istruz: TCpuIstruz): Boolean; overload;
    function    IsLoop: Boolean; overload;
    function    IsLoop(Istruz: TCpuIstruz): Boolean; overload;
    function    IsRegSegment(reg: TRegisters): Boolean;
    function    BranchDestination: Uint64;  overload;
    function    BranchDestination(Istruz: TCpuIstruz): Uint64;  overload;
    function    GenLabelCode(List: TListCpuIstruz;  var OutList: TStringList;lviewAddr: Boolean= False): Boolean; overload;
    function    GenLabelCode(List: TLinkedList<TCpuIstruz>; var OutList: TStringList;lviewAddr: Boolean= False):Boolean; overload;
    function    ToArray(List: TLinkedList<TCpuIstruz>):TListCpuIstruz;
    // Porting varie funzioni da x64dbg
    function   IsConditionalGoingToExecute(id: Mnemonics; cflags: size_t): Boolean;
    function   IsBranchGoingToExecute     (id: Mnemonics; cflags, ccx: size_t): Boolean;
    function   IsUnusual: Boolean;
    function   IsInt3: Boolean;
    function   IsNop: Boolean;
    function   isSafe64NopRegOp(op: TCpuOperand): Boolean;
    // To string Function
    function    ToString(Istruz: TCpuIstruz): string; reintroduce ; overload;
    function    ToString:string; reintroduce ; overload;
    function    OperandText(opindex: integer): string;
    // property
    property Insn    : TCpuIstruz  read FIstruz;
    property Mode    : cs_mode     read FMode      write FMode;
    property Handle  : csh         read FHandle;
    property Success : Boolean     read FSuccess ;
    property NomeFile: AnsiString  read FNomeFile  write SetNomeFile;
    property CmdStr  : string      read GetMnm;
    property Size    : Word        read GetSize;
    property Id      : Cardinal    read GetId;
    property address : UInt64      read GetAddr;

  end;

implementation
      uses  convert;

function fIntToHex(Value: UInt64): AnsiString;
var
  I,NewLen,I32 : Integer;
begin
    Result := '';
    NewLen := 1;
    I := Value shr 4;
    while I > 0 do
    begin
      Inc(NewLen);
      I := I shr 4;
    end;
    I := NewLen;
    while I mod 2 <> 0 do
      Inc(I);
    if I > NewLen then
    begin
      for I32 := 0 to (I - NewLen) - 1 do
        Result := Result + '0';
    end  ;
    Result := Result + AnsiString(IntToHex(Value,NewLen))
end;

{ TCpuOpCode }

class operator TCpuOpCode.Equal(Op1: TCpuOpCode; Op2: Mnemonics): Boolean;
begin
    Result := Op1.mnem = Op2 ;
end;

class operator TCpuOpCode.Implicit(ins: x86_insn): TCpuOpCode;
begin
     Result.mnem := Ord(ins);
end;

class operator TCpuOpCode.Implicit(mCmd: Mnemonics): TCpuOpCode;
begin
    Result.mnem := mCmd;
end;

class operator TCpuOpCode.NotEqual(Op1, Op2: TCpuOpCode): Boolean;
begin
    Result := Op1.mnem <> Op2.mnem;
end;

class operator TCpuOpCode.NotEqual(Op1:TCpuOpCode; OpCode: Mnemonics): Boolean;
begin
    Result := Op1.mnem <> OpCode;
end;

class operator TCpuOpCode.Equal(Op1, Op2: TCpuOpCode): Boolean;
begin
    Result := Op1.mnem = Op2.mnem ;
end;

function TCpuOpCode.ToString: string;
var
 str : string;
begin
    if mnem = Ord(X86_INS_ENDING) + 1 then
      Exit('loadc');

    str := gConvert.ins2str(mnem);
    if str = ''  then Result := '?'
    else              Result := str
end;

{ TCpuImm }

class operator TCpuImm.NotEqual(imm1: TCpuImm; imm2: Int64): Boolean;
begin
     Result := imm1.S <> imm2;
end;

class operator TCpuImm.NotEqual(imm1: TCpuImm; imm2: UInt64): Boolean;
begin
    Result := imm1.U <> imm2;
end;

class operator TCpuImm.NotEqual(imm1, imm2: TCpuImm): Boolean;
begin
    Result := imm1.S <> imm2.S;
end;

class operator TCpuImm.Equal(imm1, imm2: TCpuImm): Boolean;
begin
    Result := imm1.S = imm2.S;
end;

class operator TCpuImm.Equal(imm1: TCpuImm; imm2: Int64): Boolean;
begin
    Result := imm1.S = imm2;
end;

class operator TCpuImm.Equal(imm1: TCpuImm; imm2: UInt64): Boolean;
begin
    Result := imm1.U = imm2;
end;

class operator TCpuImm.Implicit(value: TCpuImm): UInt64;
begin
     Result := value.U;
end;

class operator TCpuImm.Implicit(value: TCpuImm): Int64;
begin
     Result := value.S;
end;

class operator TCpuImm.Implicit(pValue: Int64): TCpuImm;
var
  c: TCpuImm;
begin
    c.s     := pValue;
    Result  := c;

end;

function TCpuImm.ToString: string;
begin
    Result := '';

    if (u > 9) or (u < 0)  then  Result := '0x';

    Result := Result + string(fIntToHex(u))
end;

{ TCpuSeg }

class operator TCpuSeg.Equal(seg1, seg2: TCpuSeg): Boolean;
begin
    Result := seg1.seg = seg2.seg;
end;

class operator TCpuSeg.Implicit(pSeg: TSegments): TCpuSeg;
var
  c : TCpuSeg;
begin
    c.seg := pSeg;
    Result:= c;

end;

function TCpuSeg.ToString: string;
begin
    case seg of
     CS: Result :=  'cs';
     SS: Result :=  'ss';
     DS: Result :=  'ds';
     ES: Result :=  'es';
     FS: Result :=  'fs';
     GS: Result :=  'gs';
    else
        Result := '';
    end;

end;

{ TCpuReg }

class operator TCpuReg.Equal(reg1, reg2: TCpuReg): Boolean;
begin
    Result := reg1.reg = reg2.reg;
end;

class operator TCpuReg.Equal(reg1:TCpuReg; reg2: TRegisters): Boolean;
begin
    Result := reg1.reg = reg2;
end;

function TCpuReg.GetParent: Integer;
begin
    Result := Ord(REG_INVALID);

    case TRegisters(reg) of
     RAX,EAX, AX, AH, AL : Result := Ord(RAX);
     RBX,EBX, BX, BH, BL : Result := Ord(RBX);
     RCX,ECX, CX, CH, CL : Result := Ord(RCX);
     RDX,EDX, DX, DH, DL : Result := Ord(RDX);
     RBP,EBP, BP, BPL    : Result := Ord(RBP);
     RSP,ESP, SP, SPL    : Result := Ord(RSP);
     RSI,ESI, SI, SIL    : Result := Ord(RSI);
     RDI,EDI, DI, DIL    : Result := Ord(RDI);

     R8 , R8D, R8W, R8B    : Result := Ord(R8);
     R9 , R9D, R9W, R9B    : Result := Ord(R9);
     R10 ,R10D,R10W,R10B   : Result := Ord(R10);
     R11 ,R11D,R11W,R11B   : Result := Ord(R11);
     R12 ,R12D,R12W,R12B   : Result := Ord(R12);
     R13 ,R13D,R13W,R13B   : Result := Ord(R13);
     R14 ,R14D,R14W,R14B   : Result := Ord(R14);
     R15 ,R15D,R15W,R15B   : Result := Ord(R15);
    end;

end;

function TCpuReg.ToReg(regParent: Integer; rSize: Byte): TRegisters;
var
 vReg : TRegisters;
begin
  vReg :=  REG_INVALID;

  case TRegisters(regParent) of
      RAX:begin
              case rSize of
                $1: vReg := AL;
                $20:vReg := AH;
                $2: vReg := AX;
                $4: vReg := EAX;
                $8: vReg := RAX;
              end;
          end;
      RBX:begin
              case rSize of
                $1: vReg := BL;
                $20:vReg := BH;
                $2: vReg := BX;
                $4: vReg := EBX;
                $8: vReg := RBX;
              end;
          end;
      RCX:begin
               case rSize of
                  $1: vReg := CL;
                  $20:vReg := CH;
                  $2: vReg := CX;
                  $4: vReg := ECX;
                  $8: vReg := RCX;
               end;
          end;
      RDX:begin
              case rSize of
                $1: vReg := DL;
                $20:vReg := DH;
                $2: vReg := DX;
                $4: vReg := EDX;
                $8: vReg := RDX;
              end;
          end;
      RSP:begin
              case rSize of
                $1: vReg := SPL;
                $20:vReg := REG_INVALID;
                $2: vReg := SP;
                $4: vReg := ESP;
                $8: vReg := RSP;
              end;
          end;
      RBP:begin
              case rSize of
                $1: vReg := BPL;
                $20:vReg := REG_INVALID;
                $2: vReg := BP;
                $4: vReg := EBP;
                $8: vReg := RBP;
              end;
          end;
      RSI:begin
              case rSize of
                $1: vReg := SIL;
                $20:vReg := REG_INVALID;
                $2: vReg := SI;
                $4: vReg := ESI;
                $8: vReg := RSI;
              end;
          end;
      RDI:begin
              case rSize of
                $1: vReg := DIL;
                $20:vReg := REG_INVALID;
                $2: vReg := DI;
                $4: vReg := EDI;
                $8: vReg := RDI;
              end;
          end;
      R8: begin
              case rSize of
                $1: vReg := R8B;
                $20:vReg := REG_INVALID;
                $2: vReg := R8W;
                $4: vReg := R8D;
                $8: vReg := R8;
              end;
          end;
      R9: begin
              case rSize of
                $1: vReg := R9B;
                $20:vReg := REG_INVALID;
                $2: vReg := R9W;
                $4: vReg := R9D;
                $8: vReg := R9;
              end;
          end;
      R10:begin
               case rSize of
                 $1: vReg := R10B;
                 $20:vReg := REG_INVALID;
                 $2: vReg := R10W;
                 $4: vReg := R10D;
                 $8: vReg := R10;
               end;
          end;
      R11:begin
              case rSize of
                 $1: vReg := R11B;
                 $20:vReg := REG_INVALID;
                 $2: vReg := R11W;
                 $4: vReg := R11D;
                 $8: vReg := R11;
              end;
          end;
      R12:begin
              case rSize of
                $1: vReg := R12B;
                $20:vReg := REG_INVALID;
                $2: vReg := R12W;
                $4: vReg := R12D;
                $8: vReg := R12;
              end;
          end;
      R13:begin
              case rSize of
                $1: vReg := R13B;
                $20:vReg := REG_INVALID;
                $2: vReg := R13W;
                $4: vReg := R13D;
                $8: vReg := R13;
              end;
          end;
      R14:begin
              case rSize of
                $1: vReg := R14B;
                $20:vReg := REG_INVALID;
                $2: vReg := R14W;
                $4: vReg := R14D;
                $8: vReg := R14;
              end;
          end;
      R15:begin
              case rSize of
                $1: vReg := R15B;
                $20:vReg := REG_INVALID;
                $2: vReg := R15W;
                $4: vReg := R15D;
                $8: vReg := R15;
              end;
          end;
  end;
	Result := vReg;

end;

class operator TCpuReg.Implicit(pReg: TRegisters): TCpuReg;
var
  c : TCpuReg;
begin
    c.reg := pReg;
    Result:= c;
end;

class operator TCpuReg.Implicit(pReg: x86_reg): TCpuReg;
var
  c : TCpuReg;
begin
    c.reg := TRegisters(pReg);
    Result:= c;

end;

class operator TCpuReg.LessThanOrEqual(reg1, reg2: TCpuReg): Boolean;
begin
    Result:= (reg1.GetSize <= reg2.GetSize) and (reg1.GetParent = reg2.GetParent);
end;

class operator TCpuReg.NotEqual(reg1, reg2: TCpuReg): Boolean;
begin
    Result := reg1.reg <> reg2.reg;
end;

procedure TCpuReg.SetParent(const Value: Integer);
begin
    // reg non specificato esce
    if Size = 0 then  Exit;

    reg := ToReg(Value,Size);
end;

procedure TCpuReg.SetSize(const Value: Integer);
var
 regParent : Integer;
begin
    // se il size non è cambiato
    if Size = Value  then Exit;

    regParent := Parent;

    reg := ToReg(regParent,Value);
end;

class operator TCpuReg.GreaterThanOrEqual(reg1, reg2: TCpuReg): Boolean;
begin
     Result:= (reg1.GetSize >= reg2.GetSize) and (reg1.GetParent = reg2.GetParent);
end;

class operator TCpuReg.Explicit(pReg: TCpuReg): UInt8;
begin
    Result := Uint8(pReg.reg);
end;

class function TCpuReg.FromString(sReg: string): TRegisters;
begin
     Result := gConvert.str2reg(sReg) ;
end;

function TCpuReg.GetOffSet: Integer;
begin
    case TRegisters(reg)  of
       AH,
       BH,
       CH,
       DH: Exit(1);
    else
       Exit(0);
    end;
end;

function TCpuReg.GetSize: Integer;
begin
     case TRegisters(reg) of
        RAX,
        RBX,
        RCX,
        RDX,
        RBP,
        RSP,
        RSI,
        RDI,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15:  Exit(SizeOf(UInt64));
        EAX,
        EBX,
        ECX,
        EDX,
        EBP,
        ESP,
        ESI,
        EDI,
        R8D,
        R9D,
        R10D,
        R11D,
        R12D,
        R13D,
        R14D,
        R15D: Exit(SizeOf(UInt32));
        AX,
        BX,
        CX,
        DX,
        BP,
        SP,
        SI,
        DI,
        R8W,
        R9W,
        R10W,
        R11W,
        R12W,
        R13W,
        R14W,
        R15W: Exit(SizeOf(UInt16));
        AH,
        AL,
        BH,
        BL,
        CH,
        CL,
        DH,
        DL,
        BPL,
        SPL,
        SIL,
        DIL,
        R8B,
        R9B,
        R10B,
        R11B,
        R12B,
        R13B,
        R14B,
        R15B: Exit(SizeOf(UInt8));
     end;
     Result := 0;

end;

function TCpuReg.ToString: string;
var
 str : string;
begin
  (*
   VMP_PSEUDO_RET_ADDR    : x86_reg = x86_reg(Ord( X86_REG_ENDING)+1);
   VMP_PSEUDO_STUB_RET_ADR: x86_reg = x86_reg(Ord( X86_REG_ENDING)+2);
   VMP_PSEUDO_EP_VIP_CRYPT: x86_reg = x86_reg(Ord( X86_REG_ENDING)+3);
   VMP_PSEUDO_RELOC_DELTA : x86_reg = x86_reg(Ord( X86_REG_ENDING)+4);
  *)
    if      reg = TRegisters(ord( X86_REG_ENDING)+3) then   Exit('vep')
    else if reg = TRegisters(ord( X86_REG_ENDING)+2) then   Exit('vstub')
    else if reg = TRegisters(ord( X86_REG_ENDING)+4) then   Exit('vreloc')
    else if reg = TRegisters(ord( X86_REG_ENDING)+1) then   Exit('vret') ;

    str := gConvert.reg2str(reg);
    if str = ''  then Result := '?'
    else              Result := str

end;

function TCpuReg.ToString(vReg: TRegisters): string;
var
 str : string;
begin
    if      reg = TRegisters(ord( X86_REG_ENDING)+3) then   Exit('vep')
    else if reg = TRegisters(ord( X86_REG_ENDING)+2) then   Exit('vstub')
    else if reg = TRegisters(ord( X86_REG_ENDING)+4) then   Exit('vreloc')
    else if reg = TRegisters(ord( X86_REG_ENDING)+1) then   Exit('vret');

    str := gConvert.reg2str(vReg);
    if str = ''  then Result := '?'
    else              Result := str

end;

{ TCpuMem }

function TCpuMem.Assigned: Boolean;
begin
    Result := True;

    if (base = REG_INVALID) and (disp = 0) then Result := False;
end;

class operator TCpuMem.Equal(mem1, mem2: TCpuMem): Boolean;
begin
 Result :=  (mem1.seg = mem2.seg)     and
            (mem1.base = mem2.base)   and
            (mem1.index = mem2.index) and
            (mem1.scale = mem2.scale) and
            (mem1.disp = mem2.disp);
end;

function TCpuMem.ToString: string;
var
  str,temp,
  operatorText: string;
  prependPlus : Boolean;

begin
    str := '';
    prependPlus := false;

    if base.reg <> REG_INVALID then
    begin
        str      := str + base.ToString;
        prependPlus := true;
    end;
    if index.reg  <> REG_INVALID then
    begin
        if prependPlus then  str  := str + '+';

        str         := str + index.ToString;
        if scale.u > 1 then temp := Format('*%s', [scale.ToString])
        else                temp := '';
        str := str + temp;
        prependPlus := true;
    end;
    if disp.u  <> 0 then
    begin
        operatorText := '+';
        if(Integer(disp.s) < 0) and (prependPlus)then
        begin
             operatorText := '-';
             temp         := Format('0x%X', [disp.s * -1]);
        end
        else
            temp    := Format('0x%X', [disp.s]);

        if prependPlus then str  := str + operatorText;

        str  := str + temp;
    end;
    if  (disp.U = 0)  and   (base.reg = REG_INVALID)  and   (index.reg = REG_INVALID) then str  := str + '0';
    Result :=  '['+str+']';

     if seg.seg <> INVALID then
       if seg.ToString <> '' then
           Result := seg.ToString +':' + Result;

end;

{ TCpuOperand }

class operator TCpuOperand.Explicit(pRegs: TRegisters): TCpuOperand;
var
  c : TCpuOperand;
begin
    ZeroMemory(@c, SizeOf(TCpuOperand));
    c := TCpuOperand(TCpuReg(pRegs));

    Result := c;

end;

class operator TCpuOperand.Explicit(pReg: TCpuReg): TCpuOperand;
var
  c : TCpuOperand;
begin
  ZeroMemory(@c, SizeOf(TCpuOperand));
  c.Tipo := TCpuOperandTipo(T_REG);
  c.reg  := pReg;

  Result := c;
end;

class operator TCpuOperand.Explicit(pValue: TCpuImm): TCpuOperand;
var
  c : TCpuOperand;
begin
    ZeroMemory(@c, SizeOf(TCpuOperand));
    c.Tipo := TCpuOperandTipo(T_IMM);
    c.imm  := pValue;

    Result := c;

end;

class operator TCpuOperand.Equal(op1, op2: TCpuOperand): Boolean;
begin
    Result := False;

    if op1.Tipo <> op1.Tipo then Exit(False);

    case op1.Tipo of
      TIPO_INVALID: Exit(True);
      T_REG: Exit( op1.reg = op2.reg) ;
      T_IMM: Exit( op1.imm = op2.imm);
      T_MEM: Exit( op1.mem = op2.mem) ;
    end;
end;

class operator TCpuOperand.Explicit(pMem: TCpuMem): TCpuOperand;
var
  c : TCpuOperand;
begin
    ZeroMemory(@c, SizeOf(TCpuOperand));
    c.Tipo := TCpuOperandTipo(T_MEM);
    c.mem  := pMem;

    Result := c;

end;

function TCpuOperand.ToString: string;

  function MemSizeName(size: Integer): string;
    begin
         case size of
           1:  Result := 'byte ptr';
           2:  Result := 'word ptr';
           4:  Result := 'dword ptr';
           6:  Result := 'fword';
           8:  Result := 'qword ptr';
           10: Result := 'tword';
           14: Result := 'm14';
           16: Result := 'xmmword';
           28: Result := 'm28';
           32: Result := 'yword';
           64: Result := 'zword';
         else
             Result := '';
         end;
    end;

begin
    case  Tipo of
     T_REG: Result := reg.ToString;
     T_IMM: Result := imm.ToString;
     T_MEM: Result := MemSizeName(Size.u) + ' '+mem.ToString;
    else
        Result :=  '?';
    end;

end;

{ TCpuIstruz }

function TCpuIstruz.IsEq(cCmd: TCpuOpCode; opTipo: TArray<TCpuOperandTipo>): Boolean;
var
  i : Integer;
begin
    if opcode <> cCmd then  Exit(False);

    for i := 0 to High(opTipo) do
      if operands[i].Tipo <> opTipo[i] then  Exit(False);

    Result := True;
end;

function TCpuIstruz.ToString(PrintAddr: Boolean= False): string;
var
  str : string;
  i   : Integer;
begin
    str := '';
    if      prefix[0] = Ord(X86_PREFIX_LOCK) then str := 'lock '
    else if prefix[0] = Ord(X86_PREFIX_REP)  then str := 'rep '
    else if prefix[0] = Ord(X86_PREFIX_REPE) then str := 'repe '
    else if prefix[0] = Ord(X86_PREFIX_REPNE)then str := 'repne ';

    str := str + opcode.ToString;

    if opCount > 0 then
        str := str + ' ';
    for i := 0 to opCount - 1 do
    begin
        if i <> 0 then
        begin
            str := str + ',';
            str := str + ' ';
        end;
        str := str + operands[i].ToString;
    end ;
    if PrintAddr then Result := '0x'+ String(fIntToHex(address)) +': '+ str
    else              Result := str;

end;

{ TCapstone }

function TCapstone.FromCapstone(const insn: cs_insn): TCpuIstruz;
var
  instr  : TCpuIstruz;
  mem    : TCpuMem;
  imm    : TCpuImm;
  detail : cs_detail;
  x86    : cs_x86;
  op     : cs_x86_op;
  i,nR   : Integer;

begin

    instr.opcode.mnem  := Mnemonics(insn.id);
    detail := insn.detail^;

    // per evitare problemi con istruzioni inusuali
    if (detail.regs_read_count >  Length(detail.regs_read))  or  (detail.regs_write_count >  Length(detail.regs_write)) or (detail.x86.op_count > Length(detail.x86.operands)) then
    begin
        instr.opcode.mnem := Ord(X86_INS_INVALID);
        Exit;
    end;

    for i := 0 to detail.regs_read_count - 1 do
    begin
        SetLength(instr.regs_read,Length(instr.regs_read)+1);
        instr.regs_read[High(instr.regs_read)] := gConvert.convertReg(x86_reg(detail.regs_read[i]))
    end;

    if detail.regs_write_count >  Length(detail.regs_write)  then nR := Length(detail.regs_write)
    else                                                          nR := detail.regs_write_count;

    for i := 0 to detail.regs_write_count - 1 do
    begin
        SetLength(instr.regs_written,Length(instr.regs_written)+1);
        instr.regs_written[High(instr.regs_written)] := gConvert.convertReg(x86_reg(detail.regs_write[i]));
    end;

    for i := 0 to detail.groups_count - 1 do
    begin
        SetLength(instr.groups,Length(instr.groups)+1);
        instr.groups[High(instr.groups)] := detail.groups[i] ;
    end;

    x86 := detail.x86;
    CopyMemory(@instr.prefix, @x86.prefix, sizeof(instr.prefix));
    instr.address := insn.address;
    instr.size := insn.size;
    ZeroMemory(@instr.bytes,SizeOf(instr.bytes));
    CopyMemory(@instr.bytes, @insn.bytes, insn.size);
    instr.eflags  := x86.eflags.eflags;
    instr.opCount := x86.op_count;

    ZeroMemory(@instr.operands,SizeOf(instr.operands));
    if instr.opCount > Length(instr.operands) then
        instr.opCount :=  Length(instr.operands);

    for i := 0 to instr.opCount - 1 do
    begin
        op := x86.operands[i];
        if  x86_op_type(op.op.tipo) = X86_OP_MEM_ then
        begin
            mem.seg  := gConvert.convertSeg(x86_reg(op.op.mem.segment));
            mem.base := gConvert.convertReg(x86_reg(op.op.mem.base));
            mem.index:= gConvert.convertReg(x86_reg(op.op.mem.index));
            mem.scale:= op.op.mem.scale;
            mem.disp := op.op.mem.disp;
        end
        else if  x86_op_type(op.op.tipo) = X86_OP_IMM then
        begin
            imm.S := op.op.imm;
        end;

        case x86_op_type(op.op.tipo) of
          X86_OP_REG:  instr.operands[i] := TCpuOperand(gConvert.convertReg(x86_reg(op.op.reg)));
          X86_OP_IMM:  instr.operands[i] := TCpuOperand(imm);
          X86_OP_MEM_: instr.operands[i] := TCpuOperand(mem);
        end;
        instr.operands[i].size.u := op.size;
        instr.operands[i].access := op.access;
    end;
    {$IFDEF DEBUG}instr.Istr_Str := instr.ToString; {$ENDIF}
    Result := instr;
    if Result.opCount > 3 then
    begin
        Result.opcode.mnem := Ord(X86_INS_INVALID);
        Exit;
    end;
end;

function TCapstone.GenLabelCode(List: TLinkedList<TCpuIstruz>; var OutList: TStringList;lviewAddr: Boolean= False):Boolean;
var
  current: TLinkedListNode<TCpuIstruz>;
  outlst : TListCpuIstruz;
begin

   current := List.First;
   SetLength(outlst, 0);
   while current <> nil do
   begin
       outlst := outlst +  [ current.Data ];

       current := current.Next;
   end;

   Result := GenLabelCode(outlst,OutList,lviewAddr) ;

end;

function TCapstone.GenLabelCode(List: TListCpuIstruz; var OutList: TStringList;lviewAddr: Boolean= False):Boolean;
var
 i,j,nC : Integer;
 found  : Boolean;
 lLabel : TLabelList;
 sLabel : string;

 function IsRefExist(aRef: TArray<TRef>;Value: UInt64):Boolean;
 var
   k : Integer;
 begin
      Result := False;
      for k := 0 to High(aRef) do
      begin
          if aRef[k].RefFrom = Value then
              Exit(True);
      end;
 end;

 function GetLabel(Address : UInt64): string;
 var
   k : Integer;
 begin
      Result := '';
      for k := 0 to High(lLabel) do
      begin
          if lLabel[k].Addr = Address then
          begin
              Result := lLabel[k].sLabel;
              Break;
          end;
      end;
 end;

begin
     OutList.Clear;
     Result := False;

     if Length(List) < 1 then   Exit;


     if FMode = CS_MODE_32 then OutList.Add('Bits 32')
     else                       OutList.Add('Bits 64');
     OutList.Add('');
     OutList.Add(Format(';<%X>',[List[0].address]));
     OutList.Add('');

     for i := 0 to High(List) do
     begin
          if IsCFI(list[i]) then
          begin
               found := False;
               List[i].refTo := list[i].operands[0].imm.u;
               for j := 0 to High(List) do
               begin
                    if List[i].refTo = List[j].address then
                    begin
                          if IsRefExist(list[j].refFrom,List[i].refTo) then
                             found := True
                          else begin
                             found := True;
                             SetLength(list[j].refFrom, Length(list[j].refFrom)+1) ;
                             list[j].refFrom[High(list[j].refFrom)].RefFrom := List[i].refTo;
                          end;
                    end;
               end;
               if found = False then
               begin
                 List[i].refTo := 0;
               end;
          end;
     end;

     // crea label table
     nC := 0;
     for i := 0 to High(List) do
     begin
          found := False;
          for j := 0 to High(list[i].refFrom) do
          begin
               Result := True;
               found := True;
               SetLength(lLabel, Length(lLabel)+1) ;
               lLabel[High(lLabel)].Addr  := list[i].refFrom[j].RefFrom;
               lLabel[High(lLabel)].sLabel:= 'Label_'+ IntToStr(nC);
          end;
          if found then  inc(nC);
     end;

     try
         // crea il codice con label
         for i := 0 to High(List) do
         begin
              if (Length(list[i].refFrom) >  0) or (list[i].refTo <>  0) then
              begin
                   if Length(list[i].refFrom) >  0 then
                   begin
                       sLabel := Format('@%s:',[GetLabel(list[i].refFrom[0].RefFrom)]);
                       OutList.Add(sLabel);
                       if lviewAddr then
                           OutList.Add(Format('      %x:  %s',[list[i].address,list[i].ToString]))
                       else
                           OutList.Add(Format('        %s',[list[i].ToString]));
                   end;

                   if (Length(list[i].refFrom) > 0) and (List[i].refTo <> 0) then
                     OutList.Delete(OutList.Count - 1);

                   if list[i].refTo <>  0 then
                   begin
                      if lviewAddr then
                         sLabel :=  Format('     %x:  %s  @%s',[list[i].address,list[i].OpCode.ToString,GetLabel(list[i].refTo)])
                      else
                         sLabel :=  Format('       %s  @%s',[list[i].OpCode.ToString,GetLabel(list[i].refTo)]);
                      OutList.Add(sLabel);
                   end;
              end else
              begin
                  if lviewAddr then
                      OutList.Add(Format('      %x:  %s',[list[i].address,list[i].ToString]))
                  else
                      OutList.Add(Format('        %s',[list[i].ToString]));
              end;
             Result := True;
         end;
     except
        raise Exception.Create('Error in Make Label Item num: '+inttostr(i));
     end;
end;

//xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
// Legge un byte dall'indirizzo di memoria specificato
//xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
function TCapstone.ReadMemory(const hProcess : THandle; const address: UInt64; Size: DWORD; var Buf : TBuffDis): Boolean;
(*******************************************************************************)
var
  BufCnt   : NativeUInt;

begin

  Result:= ReadProcessMemory(
                hProcess,                // HANDLE hProcess,	              // handle del processo da cui leggere
                Pointer(Address),        // LPVOID lpBaseAddress,	      // Indirizzo da cui inizare la lettura
                @Buf[0],                 // LPVOID lpBuffer,	              // pointer al buffer che riceve i dati
                Size,                    // DWORD nSize,        	      // numero di byte da leggere
                BufCnt);                 // LPDWORD lpNumberOfBytesRead       // numero di byte letti effettivamente

  if not Result then SysErrorMessage(GetLastError());

end;

function TCapstone.RegName(Reg: TRegisters): string;
var
 str : string;
begin
    str := gConvert.reg2str(Reg);
    if str = ''  then Result := '?'
    else              Result := str
end;


constructor TCapstone.Create;
begin
  inherited;
  FMode        := CS_MODE_32;
  FHandle      := 0;
  FInsn        := nil;
  FInitialized := False;
  FSuccess     := False;
  FOpened      := False;
end;

destructor TCapstone.Destroy;
begin
  Close;
  inherited;
end;

function TCapstone.Open: cs_err;
begin
    Result := CS_ERR_OK;
    if not  FInitialized then
    begin
        Result := cs_open(Cardinal(CS_ARCH_X86), FMode, @FHandle);
        if Result = CS_ERR_OK then
        begin
            Result := cs_option(FHandle, Ord(CS_OPT_DETAIL), Ord(CS_OPT_ON));

            if Result = CS_ERR_OK then
            begin
                FInsn        := cs_malloc(FHandle);
                FInitialized := True;
            end;
        end;
    end;
end;

procedure TCapstone.Close;
begin
    if FInsn <> nil then
    begin
        cs_free(FInsn,1);
        FInsn := nil;
    end;
    if FHandle <> 0 then
    begin
        cs_close(FHandle);
        FHandle := 0;
    end;
    FInitialized := False;
end;

function TCapstone.ResolveOpValue(opindex : Integer): Uint64;
var
  dest : UInt64;
  op   : TCpuOperand;
begin
     dest := 0;
     op   := FIstruz.operands[opindex];
     case op.tipo of
         T_IMM:  dest := op.imm.U;
         T_REG:  dest := 0;
         T_MEM:
             begin
                 dest := op.mem.disp.U;
                 if(op.mem.base.reg = RIP) then //rip-relative
                     dest := dest + Address + Size
                 else
                     dest := dest + 0 ;
             end;
     else

     end;
     Result :=  dest;
end;

procedure TCapstone.GetRegRW(ins: Pcs_insn);
var
  reg_Read,
  reg_Write : cs_regs;
  nReg_Read,
  nReg_Write : Byte;
  i          : Integer;
  Res        : Integer;
begin

    ZeroMemory(@reg_Read,SizeOf(reg_Read));
    ZeroMemory(@reg_Write,SizeOf(reg_Write));

    Res := cs_regs_access(FHandle ,ins , PWideChar(@reg_Read[0]), @nReg_Read, PWideChar(@reg_Write[0]), @nReg_Write) ;
    if Res <> Ord(CS_ERR_OK)  then
       raise Exception.Create('[TCapstone] - Impossibile Leggere Registri');

    ins.detail^.regs_read_count := nReg_Read;
    for i := 0 to nReg_Read - 1 do
       ins.detail^.regs_read[i] := Byte(reg_Read[i]);

    ins.detail^.regs_write_count := nReg_Write;
    for i := 0 to nReg_Write - 1 do
       ins.detail^.regs_write[i] := Byte(reg_Write[i]);
end;

function TCapstone.Disassemble(addr: UInt64; const data: array of byte) : Boolean;
begin
      if not FInitialized then Exit(False);

      Result :=  Disassemble(addr, @data, MAX_DISASM_BUFFER);
end;

function TCapstone.Disassemble(addr: UInt64; data: Pointer; size: NativeUInt): Boolean;
var
  codeSize : NativeUInt;
  addr64   : Uint64;

begin
    if( data = nil ) or (size = 0) then  Exit(False);
    if not FInitialized then Exit(False);

    codeSize := size;
    addr64   := addr;

    Result := cs_disasm_iter(FHandle, data, codeSize, addr64, FInsn);

    FSuccess := Result;
    //
    //
    if not FSuccess then
        Exit(False);

    GetRegRW(FInsn);

    FIstruz := FromCapstone(FInsn^);
    //
    //
    if FIstruz.opcode.mnem = ord(X86_INS_INVALID) then
        Result := False;
end;

function TCapstone.DisAsmBuffer(addr: UInt64; data: PByte; out AInsn: TCpuIstruz): NativeUInt;
begin
    Result := 0;

    if FHandle = 0 then
    begin
        Close;
        Open;
    end;
    if not FInitialized then Exit(0);

    if not Disassemble(addr,data,MAX_DISASM_BUFFER) then Exit;

    AInsn  := FIstruz ;
    Result := FIstruz.size ;
end;

function TCapstone.DisAsmBlock(addr: UInt64; data: PByte; size: NativeUInt; out AInsn: TListCpuIstruz): NativeUInt;
var
  TotRead  : NativeUInt;

begin
    if FHandle = 0 then
    begin
        Close;
        Open;
    end;
    if not FInitialized then Exit(0);

    TotRead := 0;
    SetLength(AInsn,0);
    while TotRead <=  size do
    begin
        if not Disassemble(addr,data,MAX_DISASM_BUFFER) then Break;

        AInsn := AInsn + [ FIstruz ] ;
        NativeUInt(data) := Nativeuint(data) + FIstruz.size ;
        if TotRead > 8470 then
           TotRead := TotRead;

        if (TotRead + FIstruz.size) >= size then  Break;

        TotRead := TotRead + FIstruz.size;
    end;
    Result := Length(AInsn);
end;

function TCapstone.DisAssembleVA(VA_Addr: UInt64): Boolean;
var
  fOffset: UInt64;
  FVAddr : PByte;

  i      : Integer;
  buffer : array[0..MAX_DISASM_BUFFER-1] of Byte;
  res    : Boolean;
begin
     FSuccess := True;

     if FMpFile = nil  then
       raise Exception.Create('File non Mappato.' );

     fOffset  := VaToFileOffset(VA_Addr);
     FVAddr   := (FMpFile + fOffset);

     try
       for i := 0 to MAX_DISASM_BUFFER - 1  do
            buffer[i] := FVAddr[i];

       res := Disassemble(VA_Addr,buffer) ;
       if not res then
         FSuccess := False;
     except
       raise Exception.Create('Errore Durante DisAsm.' );
     end;
     Result := FSuccess;
end;

// porting from x64dbg
function TCapstone.DisasmBack(ip: UInt64; n: Word) : UInt64;
var
  back,uAddr: UInt64;
  abuf      : array[0..130] of UInt64;
  cmdSize   : NativeUInt;
  i,idx     : NativeUInt;
  fOffset   : UInt64;
  pVAddr    : Pbyte;
  Buffer    : TArray<Byte>;
begin
     // Round the number of back instructions to 127
     if      Int16(n) < 0   then n := 0
     else if       n > 127  then n := 127;

     // Obvious answer
     if n = 0  then Exit(ip);

     back := MAX_DISASM_BUFFER * (n + 3); // Instruction length limited to 16
     SetLength(Buffer,back);

     uAddr := ip - back;

     if FMpFile = nil  then
          raise Exception.Create('File non Mappato.' );

     fOffset  := VaToFileOffset(uAddr);
     pVAddr   := (FMpFile + fOffset);

     for i := 0 to (MAX_DISASM_BUFFER * (n + 3)) - 1  do
        buffer[i] := pVAddr[i];

     idx := 0;
     for i := 0 to back do
     begin
         if uAddr >= ip then Break;
         abuf[i mod 128] := uAddr;
                   
         if not Disassemble(uAddr,buffer[idx]) then
           cmdSize := 1
         else
           cmdsize := Size;

         uAddr := uAddr + cmdsize;
         back  := back  - cmdsize;
         idx   := idx   + cmdsize;
     end;

     if(i < n) then Exit(abuf[0])
     else
         Exit( abuf[(i - n + 128) mod 128] );
end;

procedure TCapstone.Disassemble(FileOffset: UInt64);
var
    FVAddr : PByte;

  i      : Integer;
  buffer : array[0..MAX_DISASM_BUFFER-1] of Byte;
  res    : Boolean;
begin

     if FMpFile = nil  then
       raise Exception.Create('File non Mappato.' );

     FVAddr := (FMpFile + FileOffset);

     try
       for i := 0 to MAX_DISASM_BUFFER - 1  do
            buffer[i] := FVAddr[i];

       res := Disassemble(FileOffset,buffer) ;
       if not res then
         FSuccess := False;
     except
       raise Exception.Create('Errore Durante DisAsm.' );
     end;
end;

procedure TCapstone.Disassemble(const hProc: THandle ;VA_Addr: UInt64);
var
  OldProtect : DWORD;
  MemInfo    : MEMORY_BASIC_INFORMATION;
  buffer     : TBuffDis;
  res        : Boolean;
begin

    if hProc = INVALID_HANDLE_VALUE then
        raise Exception.Create('Invalid Handle.' );

     VirtualQueryEx(hProc, Pointer(VA_Addr), MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

     OldProtect := MemInfo.AllocationProtect;
     VirtualProtectEx(hProc, Pointer(VA_Addr), 20, PAGE_EXECUTE_READWRITE, OldProtect);


     try

       ReadMemory(hProc,VA_Addr,MAX_DISASM_BUFFER,buffer);

       res := Disassemble(VA_Addr,buffer) ;
       if not res then
         FSuccess := False;

     except
       raise Exception.Create('Errore Durante DisAsm.' );
     end;
end;

function TCapstone.RvaToOffset(Rva: UInt64): UInt64;
var
  i      : Word;
  Img    : PImageSectionHeader;
  Offset,
  Limit  : UInt64;
  numSec   : Word;
begin
    Result := 0;
    Offset := Rva;
    Img    := PImageSectionHeader(FNT);

    if FMode = CS_MODE_32 then
        Inc(PImageNtHeaders32(Img))
    else
        Inc(PImageNtHeaders64(Img)) ;

    if (Rva < Img.PointerToRawData) then
    begin
        Result := Rva;
        Exit;
    end;

    i := 0;
    if FMode = CS_MODE_32 then
         numSec := PImageNtHeaders32(FNT)^.FileHeader.NumberOfSections
    else
         numSec := PImageNtHeaders64(FNT)^.FileHeader.NumberOfSections ;

    while i < numSec do
    begin
        if (Img.SizeOfRawData <> 0) then
        begin
            Limit := Img.SizeOfRawData;
        end
        else
            Limit := Img.Misc.VirtualSize;
        if (Rva >= Img.VirtualAddress) and (Rva < (Img.VirtualAddress + Limit)) then
        begin
            if (Img.PointerToRawData <> 0) then
            begin
                Dec(Offset, Img.VirtualAddress);
                Inc(Offset, Img.PointerToRawData);
            end;
            Result := Offset;
            Break;
        end;
        Inc(Img);
        Inc(i);
    end;
end;

procedure TCapstone.SetNomeFile(const Value: AnsiString);
begin
    FNomeFile := Value;
    OpenDisFile(FNomeFile);
end;

procedure TCapstone.OpenDisFile(const AFile: AnsiString);
var
  PDosHeader: PImageDosHeader;
  PNtHeader : Pointer;
  
begin
    if FOpened then CloseDisFile;

    FOpened := True;

    FhFile     := CreateFileA(PAnsiChar(AFile), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    FoFile     := CreateFileMappingA(FhFile, nil, PAGE_READONLY, 0, 0, nil);
    FMpFile    := MapViewOfFile(FoFile, FILE_MAP_READ, 0, 0, 0);
    PDosHeader := PImageDosHeader(FMpFile);

    if PDosHeader.e_magic <> IMAGE_DOS_SIGNATURE then  Exit;
	
	  PNtHeader := PImageNtHeaders32(UInt64(PDosHeader) + PDosHeader._lfanew) ;
    if PImageNtHeaders32(PNtHeader).OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC then FMode := CS_MODE_64
    else                                                                                      FMode := CS_MODE_32;

    if FMode =CS_MODE_32 then
    begin
       PNtHeader := PImageNtHeaders32(UInt64(PDosHeader) + UInt32(PDosHeader._lfanew)) ;
       if PImageNtHeaders32(PNtHeader).Signature <> IMAGE_NT_SIGNATURE then Exit;
    end
    else begin
       PNtHeader := PImageNtHeaders64(UInt64(PDosHeader) + UInt32(PDosHeader._lfanew));
       if PImageNtHeaders64(PNtHeader).Signature <> IMAGE_NT_SIGNATURE then Exit;
    end;

    FNT := PNtHeader;
    CloseHandle(FhFile);

    if FInitialized then
    begin
        Close;
        Open;
    end else
    begin
        Open;
    end;

end;

procedure TCapstone.CloseDisFile;
begin
    if FOpened then
    begin
        FOpened := False;
        UnMapViewOfFile(FMpFile);
        CloseHandle(FoFile);
        CloseHandle(FhFile);
    end;
end;

Function TCapstone.VaToFileOffset(dwVA: UInt64): UInt64;
(*******************************************************************************)
begin
     if FMode = CS_MODE_32 then
     begin
          if (dwVA > PImageNtHeaders32(FNT)^.OptionalHeader.ImageBase) then
              Result := RvaToOffset(dwVA - PImageNtHeaders32(FNT)^.OptionalHeader.ImageBase)
          else
              Result := 0;
     end else
     begin
          if (dwVA > DWord(PImageNtHeaders64(FNT)^.OptionalHeader.ImageBase)) then
              Result := RvaToOffset(dwVA - PImageNtHeaders64(FNT)^.OptionalHeader.ImageBase)
          else
              Result := 0;
     end

end;


function TCapstone.FileOffsetToRva(dwFileOffset: UInt64): UInt64;
(*******************************************************************************)
var
  x      : Word;
  Img    : PImageSectionHeader;
  numSec : Word;
begin
    Result := 0;
    Img    := PImageSectionHeader(FNT);
    x      := 0;

    if FMode = CS_MODE_32 then
         numSec := PImageNtHeaders32(FNT)^.FileHeader.NumberOfSections
    else
         numSec := PImageNtHeaders64(FNT)^.FileHeader.NumberOfSections ;

    while x < numSec do
    begin
        if ((dwFileOffset >= Img.PointerToRawData) and (dwFileOffset < Img.PointerToRawData + Img.SizeOfRawData)) then
        begin
            Result := dwFileOffset - Img.PointerToRawData + Img.VirtualAddress;
            Break;
        end;
        Inc(Img);
        Inc(x);
    end;
end;


function TCapstone.FileOffsetToVa(dwFileOffset: UInt64): UInt64;
(*******************************************************************************)
begin
     if FMode = CS_MODE_32 then
         Result := FileOffsetToRva(dwFileOffset) + PImageNtHeaders32(FNT)^.OptionalHeader.ImageBase
     else
         Result := FileOffsetToRva(dwFileOffset) + PImageNtHeaders64(FNT)^.OptionalHeader.ImageBase
end;

function TCapstone.Internal_Ingroup(Istruz:TCpuIstruz; group: cs_group_type):Boolean;
var
  i : Integer;
begin
    Result := False;
    for i := 0 to High(istruz.groups) do
      if istruz.groups[i] = Ord(group) then
        Exit(True)

end;

function TCapstone.InGroup(group: cs_group_type): Boolean;
begin
    Result := InGroup(FIstruz,group) ;
end;

function TCapstone.InGroup(Istruz: TCpuIstruz; group: cs_group_type): Boolean;
var
  id : x86_insn;
begin

    if group = CS_GRP_PRIVILEGE then
    begin
         id := x86_insn(Istruz.OpCode.mnem);
        // I/O instructions
        if (id = X86_INS_OUT) or (id = X86_INS_OUTSB) or (id = X86_INS_OUTSD) or (id = X86_INS_OUTSW) or
           (id = X86_INS_IN)  or (id = X86_INS_INSB)  or (id = X86_INS_INSD)  or (id = X86_INS_INSW)  or
            // system instructions
           (id = X86_INS_RDMSR) or (id = X86_INS_SMSW)  then
            Exit(true);
    end;
    Result := Internal_Ingroup(Istruz, group);

end;

function TCapstone.IsLoop: Boolean;
begin
    if not FSuccess then Exit(False);

    Result := IsLoop(FIstruz) ;
end;

function TCapstone.IsLoop(Istruz: TCpuIstruz): Boolean;
begin

    case x86_insn(Istruz.opcode.mnem) of
      X86_INS_LOOP,
      X86_INS_LOOPE,
      X86_INS_LOOPNE : Result := True;
    else
      Result := False;
    end;
end;

function TCapstone.IsJcc: Boolean;
begin
    Result := IsJcc(FIstruz);
end;

function TCapstone.IsJcc(Istruz: TCpuIstruz): Boolean;
begin
   if(InGroup(Istruz,CS_GRP_JUMP)) and  (x86_insn(Istruz.opcode.mnem) <> X86_INS_JMP) then
     Result := True
   else
     Result := False;
end;

function TCapstone.IsJmp: Boolean;
begin
     Result := IsJmp(FIstruz);
end;

function TCapstone.IsJmp(Istruz: TCpuIstruz): Boolean;
begin
    Result := x86_insn(Istruz.opcode.mnem) = X86_INS_JMP;
end ;

function TCapstone.IsCall: Boolean;
begin
     Result := IsCall(FIstruz);
end;

function TCapstone.IsCall(Istruz: TCpuIstruz): Boolean;
begin
    Result := InGroup(Istruz,CS_GRP_CALL)
end;

function TCapstone.IsRet: Boolean;
begin
    Result := IsRet(FIstruz);
end;

function TCapstone.IsRet(Istruz: TCpuIstruz): Boolean;
begin
    Result := InGroup(Istruz,CS_GRP_RET)
end;

function TCapstone.IsCFI: Boolean;
begin
   Result := IsCFI(FIstruz);
end;

function TCapstone.IsCFI(Istruz: TCpuIstruz): Boolean;
begin
    if IsJcc(Istruz)        then Exit(True)
    else if IsJmp(Istruz)   then Exit(True)
    else if IsCall(Istruz)  then Exit(True)
    else if IsRet(Istruz)   then Exit(True)
    else if IsLoop(Istruz)  then Exit(True)
    else
         Exit(False)
end;

function TCapstone.BranchDestination: Uint64;
begin
    if not FSuccess then Exit(0);

    Result := BranchDestination(FIstruz)

end;

function TCapstone.BranchDestination(Istruz: TCpuIstruz): Uint64;
var
  op : TCpuOperand;
begin

    if(InGroup(Istruz,CS_GRP_JUMP)) or (InGroup(Istruz,CS_GRP_CALL)) or (IsLoop(Istruz)) then
    begin
        op := Istruz.operands[0];
        if op.Tipo = T_IMM then
             Exit(op.imm.U);
    end;
    Result := 0;
end;

function TCapstone.GetAddr: UInt64;
begin
    if not FSuccess then Exit(0);

    Result := FIstruz.address;
end;

function TCapstone.ToArray(List: TLinkedList<TCpuIstruz>): TListCpuIstruz;
var
  Curr :TLinkedListNode<TCpuIstruz> ;
begin
    Curr := List.First;
    Result := [];
    while Curr <> nil   do
    begin
        Result := Result + [ Curr.Data ] ;
        Curr := Curr.Next;
    end;

end;

function TCapstone.Tostring:string;
begin
    Result   :=  FIstruz.ToString;
end;

function TCapstone.Tostring(Istruz: TCpuIstruz):string;
begin
    Result   := Istruz.ToString;
end;

function TCapstone.GetId: Cardinal;
begin
     if not FSuccess then Exit(0);

     Result := FIstruz.opcode.mnem;
end;

function TCapstone.GetMnm: string;
begin
     if not FSuccess then Exit('');

     Result := FIstruz.opcode.ToString;
end;

function TCapstone.GetMnm(OpCode: Integer): string;
var
  tmpOpcode : TCpuOpcOde;
begin
     tmpOpcode.mnem := OpCode;
     Result         := tmpOpcode.ToString;
end;

function TCapstone.GetSize: Word;
begin
     if not FSuccess then Exit(0);

     Result := FIstruz.size
end;

function TCapstone.IsRegSegment(reg: TRegisters): Boolean;
begin
     Result := False;
     case TSegments(reg) of
       CS,SS,DS,
       ES,FS,GS: Result := True;
     end;
end;

function TCapstone.OperandText( opindex : integer ):string;
var
  op           : TCpuOperand;
  temp         : string;

begin
    op := FIstruz.operands[opindex];

    if op.mem.base.reg = RIP then
    begin
        temp    := Format('%X', [Address + op.mem.disp.U + Size]);
        result  := '['+temp+']';
    end else
    begin
        result := FIstruz.operands[opindex].ToString;
    end;
end;

// porting from x64dbg
function TCapstone.isSafe64NopRegOp(op : TCpuOperand):Boolean;
 begin
     if op.tipo <> T_REG then Exit(true); //a non-register is safe

     if FMode = CS_MODE_64 then
     begin
         case op.reg.reg of
             EAX,
             EBX,
             ECX,
             EDX,
             EBP,
             ESP,
             ESI,
             EDI,
             R8D,
             R9D,
             R10D,
             R11D,
             R12D,
             R13D,
             R14D,
             R15D:
                 Result := false; //32 bit register modifications clear the high part of the 64 bit register
             else
                 Result := true; //all other registers are safe
         end;
     end
     else Exit(true);
end;

// porting from x64dbg
function TCapstone.IsNop:Boolean;
  var
    ops : array[0..3] of TCpuOperand;
    op  : TCpuOperand;
    reg : TCpuReg;
    mem : TCpuMem;
    i   : Integer;

  begin
      if  not FSuccess then   Exit(false);

      for i  := 0 to High(FIstruz.operands) do
          ops[i] := FIstruz.operands[i];

      case x86_insn(GetId) of

          X86_INS_NOP,
          X86_INS_PAUSE,
          X86_INS_FNOP:    Exit(true);  // nop
          X86_INS_MOV,
          X86_INS_CMOVA,
          X86_INS_CMOVAE,
          X86_INS_CMOVB,
          X86_INS_CMOVBE,
          X86_INS_CMOVE,
          X86_INS_CMOVNE,
          X86_INS_CMOVG,
          X86_INS_CMOVGE,
          X86_INS_CMOVL,
          X86_INS_CMOVLE,
          X86_INS_CMOVO,
          X86_INS_CMOVNO,
          X86_INS_CMOVP,
          X86_INS_CMOVNP,
          X86_INS_CMOVS,
          X86_INS_CMOVNS,
          X86_INS_MOVAPS,
          X86_INS_MOVAPD,
          X86_INS_MOVUPS,
          X86_INS_MOVUPD,
          X86_INS_XCHG:
              // mov edi, edi
              Exit( (ops[0].tipo = T_REG)  and  (ops[1].tipo = T_REG)  and  (ops[0].reg = ops[1].reg)  and (isSafe64NopRegOp(ops[0])) );
          X86_INS_LEA:
          begin
              // lea eax, [eax + 0]
              reg := ops[0].reg;
              mem := ops[1].mem;
              Exit( (ops[0].tipo = T_REG)  and  (ops[1].tipo = T_MEM)  and  (mem.disp = 0)  and
                     ( ((mem.index.reg = REG_INVALID)  and  (mem.base = reg))  or
                       ((mem.index = reg)  and  (mem.base.reg = REG_INVALID)  and  (mem.scale = 1)))  and  (isSafe64NopRegOp(ops[0])) );
          end;
          X86_INS_JMP,
          X86_INS_JA,
          X86_INS_JAE,
          X86_INS_JB,
          X86_INS_JBE,
          X86_INS_JE,
          X86_INS_JNE,
          X86_INS_JG,
          X86_INS_JGE,
          X86_INS_JL,
          X86_INS_JLE,
          X86_INS_JO,
          X86_INS_JNO,
          X86_INS_JP,
          X86_INS_JNP,
          X86_INS_JS,
          X86_INS_JNS,
          X86_INS_JECXZ,
          X86_INS_JRCXZ,
          X86_INS_JCXZ:
              begin
                  // jmp 0
                  op := ops[0];
                  Exit( (op.tipo = T_IMM)  and  (op.imm.U = Address + Size) );
              end;
          X86_INS_SHL,
          X86_INS_SHR,
          X86_INS_ROL,
          X86_INS_ROR,
          X86_INS_SAR,
          X86_INS_SAL:
              begin
                  // shl eax, 0
                  op := ops[1];
                  Exit( (op.tipo = T_IMM)  and  (op.imm.U = 0)  and  (isSafe64NopRegOp(ops[0])) );
              end;
          X86_INS_SHLD,
          X86_INS_SHRD:
              begin
                  // shld eax, ebx, 0
                  op := ops[2];
                  Exit( (op.tipo = T_IMM)  and  (op.imm.U = 0)  and  (isSafe64NopRegOp(ops[0]))  and  (isSafe64NopRegOp(ops[1])) );
              end;
          else
              Exit(false);
      end;
end;

function TCapstone.IsInt3:Boolean;
var
   op : TCpuOperand;
begin
     if not FSuccess then  Exit(False);

     case x86_insn(GetId) of
        X86_INS_INT3: Exit(true);
        X86_INS_INT:
              begin
                  op := Fistruz.operands[0];
                  Exit( (op.tipo = T_IMM ) and  (op.imm.U = 3) );
              end;
     else
         Exit(false);
     end;
end;

function TCapstone.IsUnusual: Boolean;
var
  id : x86_insn;
begin
     id := x86_insn(GetId);
     Exit( (InGroup(CS_GRP_PRIVILEGE))or (InGroup(CS_GRP_IRET))  or (InGroup(CS_GRP_INVALID))
             or (id = X86_INS_RDTSC)  or (id = X86_INS_SYSCALL) or (id = X86_INS_SYSENTER) or (id = X86_INS_CPUID)
             or (id = X86_INS_RDTSCP) or (id = X86_INS_RDRAND)  or (id = X86_INS_RDSEED)   or (id = X86_INS_UD2)
             or (id = X86_INS_UD2B) );
end;

function TCapstone.MemSizeName(size: Integer): string;
begin
     case size of
       1:  Result := 'byte';
       2:  Result := 'word';
       4:  Result := 'dword';
       6:  Result := 'fword';
       8:  Result := 'qword';
       10: Result := 'tword';
       14: Result := 'm14';
       16: Result := 'xmmword';
       28: Result := 'm28';
       32: Result := 'yword';
       64: Result := 'zword';
     else
         Result := '';
     end;
end;

function TCapstone.IsBranchGoingToExecute( id :Mnemonics; cflags, ccx : size_t):Boolean;
var
   bCF, bPF, bZF, bSF, bOF : Boolean;
 begin
     bCF := (cflags and (1  shl  0)) <> 0;
     bPF := (cflags and (1  shl  2)) <> 0;
     bZF := (cflags and (1  shl  6)) <> 0;
     bSF := (cflags and (1  shl  7)) <> 0;
     bOF := (cflags and (1  shl  11)) <> 0;
     case x86_insn(id) of
         X86_INS_CALL,
         X86_INS_LJMP,
         X86_INS_JMP,
         X86_INS_RET,
         X86_INS_RETF,
         X86_INS_RETFQ: Exit(true);
         X86_INS_JAE:   Exit( not bCF);                  //jump short if above or equal
         X86_INS_JA:    Exit( (not bCF)  and   (not bZF));   //jump short if above
         X86_INS_JBE:   Exit(bCF  or  bZF);              //jump short if below or equal/not above
         X86_INS_JB:    Exit(bCF);                       //jump short if below/not above nor equal/carry
         X86_INS_JCXZ,                                   //jump short if ecx register is zero
         X86_INS_JECXZ,                                  //jump short if ecx register is zero
         X86_INS_JRCXZ: Exit(ccx = 0);                   //jump short if rcx register is zero
         X86_INS_JE:    Exit(bZF);                       //jump short if equal
         X86_INS_JGE:   Exit(bSF = bOF);                 //jump short if greater or equal
         X86_INS_JG:    Exit( (not bZF)  and  (bSF = bOF));  //jump short if greater
         X86_INS_JLE:   Exit(bZF  or  bSF <> bOF);       //jump short if less or equal/not greater
         X86_INS_JL:    Exit(bSF <> bOF);                //jump short if less/not greater
         X86_INS_JNE:   Exit( not bZF);                  //jump short if not equal/not zero
         X86_INS_JNO:   Exit( not bOF);                  //jump short if not overflow
         X86_INS_JNP:   Exit( not bPF);                  //jump short if not parity/parity odd
         X86_INS_JNS:   Exit( not bSF);                  //jump short if not sign
         X86_INS_JO:    Exit(bOF);                       //jump short if overflow
         X86_INS_JP:    Exit(bPF);                       //jump short if parity/parity even
         X86_INS_JS:    Exit(bSF);                       //jump short if sign
         X86_INS_LOOP:  Exit(ccx <> 0);                  //decrement count; jump short if ecx!=0
         X86_INS_LOOPE: Exit((ccx <> 0)  and  (bZF));    //decrement count; jump short if ecx!=0 and zf=1
         X86_INS_LOOPNE:Exit((ccx <> 0)  and  (not bZF));//decrement count; jump short if ecx!=0 and zf=0
     else
         Exit(false);
     end;
end;

function TCapstone.IsConditionalGoingToExecute( id : Mnemonics; cflags: size_t):Boolean;
var
   bCF, bPF, bZF, bSF, bOF : Boolean;
begin
     bCF := (cflags and (1  shl  0)) <> 0;
     bPF := (cflags and (1  shl  2)) <> 0;
     bZF := (cflags and (1  shl  6)) <> 0;
     bSF := (cflags and (1  shl  7)) <> 0;
     bOF := (cflags and (1  shl  11)) <> 0;
     case x86_insn(id) of
         X86_INS_CMOVA:    Exit( not bCF  and   not bZF); //conditional move - above/not below nor equal
         X86_INS_CMOVAE:   Exit( not bCF);                //conditional move - above or equal/not below/not carry
         X86_INS_CMOVB:    Exit(bCF);                     //conditional move - below/not above nor equal/carry
         X86_INS_CMOVBE:   Exit(bCF  or  bZF);            //conditional move - below or equal/not above
         X86_INS_CMOVE:    Exit(bZF);                     //conditional move - equal/zero
         X86_INS_CMOVG:    Exit( not bZF  and  bSF = bOF);//conditional move - greater/not less nor equal
         X86_INS_CMOVGE:   Exit(bSF = bOF);               //conditional move - greater or equal/not less
         X86_INS_CMOVL:    Exit(bSF <> bOF);              //conditional move - less/not greater nor equal
         X86_INS_CMOVLE:   Exit(bZF  or  bSF <> bOF);     //conditional move - less or equal/not greater
         X86_INS_CMOVNE:   Exit( not bZF);                //conditional move - not equal/not zero
         X86_INS_CMOVNO:   Exit( not bOF);                //conditional move - not overflow
         X86_INS_CMOVNP:   Exit( not bPF);                //conditional move - not parity/parity odd
         X86_INS_CMOVNS:   Exit( not bSF);                //conditional move - not sign
         X86_INS_CMOVO:    Exit(bOF);                     //conditional move - overflow
         X86_INS_CMOVP:    Exit(bPF);                     //conditional move - parity/parity even
         X86_INS_CMOVS:    Exit(bSF);                     //conditional move - sign
         X86_INS_FCMOVBE:  Exit(bCF  or  bZF);            //fp conditional move - below or equal
         X86_INS_FCMOVB:   Exit(bCF);                     //fp conditional move - below
         X86_INS_FCMOVE:   Exit(bZF);                     //fp conditional move - equal
         X86_INS_FCMOVNBE: Exit( not bCF  and   not bZF); //fp conditional move - not below or equal
         X86_INS_FCMOVNB:  Exit( not bCF);                //fp conditional move - not below
         X86_INS_FCMOVNE:  Exit( not bZF);                //fp conditional move - not equal
         X86_INS_FCMOVNU:  Exit( not bPF);                //fp conditional move - not unordered
         X86_INS_FCMOVU:   Exit(bPF);                     //fp conditional move - unordered
         X86_INS_SETA:     Exit( not bCF  and   not bZF); //set byte on condition - above/not below nor equal
         X86_INS_SETAE:    Exit( not bCF);                //set byte on condition - above or equal/not below/not carry
         X86_INS_SETB:     Exit(bCF);                     //set byte on condition - below/not above nor equal/carry
         X86_INS_SETBE:    Exit(bCF  or  bZF);            //set byte on condition - below or equal/not above
         X86_INS_SETE:     Exit(bZF);                     //set byte on condition - equal/zero
         X86_INS_SETG:     Exit( not bZF  and  bSF = bOF);//set byte on condition - greater/not less nor equal
         X86_INS_SETGE:    Exit(bSF = bOF);               //set byte on condition - greater or equal/not less
         X86_INS_SETL:     Exit(bSF <> bOF);              //set byte on condition - less/not greater nor equal
         X86_INS_SETLE:    Exit(bZF  or  bSF <> bOF);     //set byte on condition - less or equal/not greater
         X86_INS_SETNE:    Exit( not bZF);                //set byte on condition - not equal/not zero
         X86_INS_SETNO:    Exit( not bOF);                //set byte on condition - not overflow
         X86_INS_SETNP:    Exit( not bPF);                //set byte on condition - not parity/parity odd
         X86_INS_SETNS:    Exit( not bSF);                //set byte on condition - not sign
         X86_INS_SETO:     Exit(bOF);                     //set byte on condition - overflow
         X86_INS_SETP:     Exit(bPF);                     //set byte on condition - parity/parity even
         X86_INS_SETS:     Exit(bSF);                     //set byte on condition - sign
     else
         Exit(true);
     end;
 end;

end.

