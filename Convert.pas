unit Convert;

interface
  uses System.Generics.Collections,Capstone,CapstoneX86;

type

  TConvert = class
    private
      Fstr2reg : TDictionary<string,TRegisters>;
      Freg2str : TDictionary<TRegisters,string>;
      Fstr2ins : TDictionary<string,Mnemonics>;
      Fins2str : TDictionary<Mnemonics,string>;

      function k2v(const m : TDictionary<string,TRegisters>; const k: string):     TRegisters ; overload;
      function k2v(const m : TDictionary<TRegisters,string>; const k: TRegisters): string;overload;
      function k2v(const m : TDictionary<string,Mnemonics>;  const k: string):     Mnemonics; overload;
      function k2v(const m : TDictionary<Mnemonics,string>;  const k: Mnemonics):  string ; overload;

    public
      procedure Init;
      constructor Create;
      destructor  Destroy;override;
      function str2reg(const str: string): TRegisters;
      function reg2str(reg : TRegisters ): string;
      function str2ins(const str: string): Mnemonics;
      function ins2str(ins: Mnemonics): string;

      function Str2Seg(seg: string): TSegments;
      function convertReg(reg : x86_reg): TRegisters; overload;
      function convertReg(reg: TCpuReg): TRegisters;  overload;
      function convertSeg(reg : x86_reg): TSegments; overload;
      function convertSeg(reg: TCpuSeg): TSegments;  overload;
  end;

  var
    gConvert : TConvert;

implementation
       uses CapstoneApi,System.SysUtils;

{ TConvert }

function TConvert.convertReg(reg: TCpuReg): TRegisters;
var
  n : Integer;
begin
    Result := REG_INVALID;

    n := ord(X86_REG_R15W);
    if   n = ord(R15W) then
       Result := TRegisters(reg.reg);
end;

function TConvert.convertReg(reg: x86_reg): TRegisters;
var
  n : Integer;
begin
    Result := REG_INVALID;

    n := ord(X86_REG_R15W);
    if   n = ord(R15W) then
       Result := TRegisters(reg);
end;

function TConvert.Str2Seg(seg: string): TSegments;
begin
    seg := Uppercase(seg);
    if      seg = 'CS' then  Result :=  CS
    else if seg = 'SS' then  Result :=  SS
    else if seg = 'DS' then  Result :=  DS
    else if seg = 'ES' then  Result :=  ES
    else if seg = 'FS' then  Result :=  FS
    else if seg = 'GS' then  Result :=  GS
    else                     Result := INVALID;

end;

function TConvert.convertSeg(reg: x86_reg): TSegments;
begin
    case reg of
     X86_REG_INVALID: Result :=  INVALID;
     X86_REG_CS:      Result :=  CS;
     X86_REG_SS:      Result :=  SS;
     X86_REG_DS:      Result :=  DS;
     X86_REG_ES:      Result :=  ES;
     X86_REG_FS:      Result :=  FS;
     X86_REG_GS:      Result :=  GS;
    else
     Result := INVALID;
    end;

end;

function TConvert.convertSeg(reg: TCpuSeg): TSegments;
begin
    case x86_reg(reg.seg) of
     X86_REG_INVALID: Result :=  INVALID;
     X86_REG_CS:      Result :=  CS;
     X86_REG_SS:      Result :=  SS;
     X86_REG_DS:      Result :=  DS;
     X86_REG_ES:      Result :=  ES;
     X86_REG_FS:      Result :=  FS;
     X86_REG_GS:      Result :=  GS;
    else
     Result := INVALID;
    end;

end;

constructor TConvert.Create;
begin
    Fstr2reg := TDictionary<string,TRegisters>.Create;
    Freg2str := TDictionary<TRegisters,string>.Create;
    Fstr2ins := TDictionary<string,Mnemonics>.Create;
    Fins2str := TDictionary<Mnemonics,string>.Create;
end;

destructor TConvert.Destroy;
begin
    Fstr2reg.Free;
    Freg2str.Free;
    Fstr2ins.Free;
    Fins2str.Free;


end;

procedure TConvert.Init;
var
  cDisAsm: TCapstone;
  i      : Integer;
  regname,
  insname: string;
begin
    cDisAsm := TCapstone.Create;
    try
      if cDisAsm.Open = CS_ERR_OK then
      begin
          for i := 0 to ord(X86_REG_ENDING) - 1 do
          begin
              if i = Ord(X86_REG_INVALID) then
                  continue;
              regname := string(cs_reg_name(cDisAsm.Handle, i) );
              if regname <> '' then
              begin
                  Fstr2reg.Add(regname,TRegisters(i));
                  Freg2str.Add(TRegisters(i), regname);
              end;
          end;

          for i := 0 to Ord(X86_INS_ENDING) - 1 do
          begin
              if i = Ord(X86_INS_INVALID) then
                  continue;
              insname := string(cs_insn_name(cDisAsm.Handle, i));
              if insname <> '' then
              begin
                  Fstr2ins.Add(insname, Mnemonics(i));
                  Fins2str.Add(Mnemonics(i), insname);
              end;
          end ;

          cDisAsm.Close;
      end;
    finally
      cDisAsm.Free
    end;
end;

function TConvert.str2reg(const str: string): TRegisters;
begin
    Result := k2v(Fstr2reg,str);
end;

function TConvert.reg2str(reg: TRegisters): string;
begin
    Result := k2v(Freg2str,reg);
end;

function TConvert.str2ins(const str: string): Mnemonics;
begin
    Result := k2v(Fstr2ins,str);
end;

function TConvert.ins2str(ins: Mnemonics): string;
begin
    Result := k2v(Fins2str,ins);
end;

function TConvert.k2v(const m: TDictionary<string, TRegisters>; const k: string): TRegisters;
begin
    Result := REG_INVALID;
    if m.Count = 0 then Exit;

    if m.ContainsKey(k) then
      Result := m[k];
end;

function TConvert.k2v(const m: TDictionary<TRegisters, string>; const k: TRegisters): string;
begin
    Result := '';
    if m.Count = 0 then Exit;

    if m.ContainsKey(k) then
      Result := m[k];
end;

function TConvert.k2v(const m: TDictionary<string, Mnemonics>; const k: string): Mnemonics;
begin
    Result := 0;
    if m.Count = 0 then Exit;

    if m.ContainsKey(k) then
      Result := m[k];
end;

function TConvert.k2v(const m: TDictionary<Mnemonics, string>; const k: Mnemonics): string;
begin
    Result := '';
    if m.Count = 0 then Exit;

    if m.ContainsKey(k) then
      Result := m[k];
end;

initialization

 gConvert := TConvert.Create;
 gConvert.Init;

finalization
 gConvert.Free;

end.
