# Capstone4Delphi
 Capstone Disassembler Library Binding for Delphi . [Capstone Disassembler Library](http://www.capstone-engine.org/)
 
## Usage

  Included is the wrapper class `TCapstone` in `Capstone.pas`, very flexible and with many features,Creation, comparison, conversion etc .. .
  The example below is incomplete. 
  
~~~pas
uses
  SysUtils, Classes, Capstone, CapstoneCmn, CapstoneApi;
var
  disasm    : TCapstone;
  addr      : UInt64;
  insn      : TCpuIstruz;
  AInsn     : TListCpuIstruz;
  stream    : TMemoryStream;
  filename  : string;
  nIstruz,i : NativeUInt;
  reg1,reg2 : TCpuReg;
begin
    if ParamCount = 0 then
    begin
        WriteLn('test <filename>');
        Halt(1);
    end;
    filename := ParamStr(1);
    if not FileExists(filename) then
    begin
        WriteLn(Format('File %s not found', [filename]));
        Halt(1);
    end;
    stream := TMemoryStream.Create;
    try
      stream.LoadFromFile(filename);
      stream.Position := 0;
      disasm := TCapstone.Create;
      try
        disasm.Mode := CS_MODE_32;
        addr := 0;
        if disasm.Open = CS_ERR_OK then
        begin
            try
              nIstruz := disasm.DisAsmBlock(addr,stream.Memory, stream.Size,AInsn);
              for i := 0 to nIstruz - 1 do
              begin
                  insn := AInsn[i];
                  if disasm.IsJcc(insn)      then  WriteLn(Format('[Jcc Group Dest: %x] %x  %s', [disasm.BranchDestination(insn), insn.address, insn.ToString]))
                  else if disasm.IsCall(insn)then  WriteLn(Format('[Call Group Dest: %x] %x  %s', [disasm.BranchDestination(insn),insn.address, insn.ToString]))
                  else if disasm.Isjmp(insn) then  WriteLn(Format('[jmp Group Dest: %x] %x  %s', [disasm.BranchDestination(insn),insn.address, insn.ToString]))
                  else if disasm.IsRet(insn) then  WriteLn(Format('[ret Group] %x  %s', [insn.address, insn.ToString]))
                  else
                     WriteLn(Format('%x  %s', [insn.address, insn.ToString]));
              end;
              reg1.reg := EAX;
              reg1.size := 1;
              reg2.reg  := ECX;
              reg2.Parent := reg1.Parent;
            except
              raise Exception.Create('Error Decompiler!');

            end;
        end else
        begin
            WriteLn('ERROR!');
        end;
      finally
        disasm.Free;
      end;
    finally
      stream.Free;
    end;
end.
~~~
