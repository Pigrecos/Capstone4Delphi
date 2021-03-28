unit Collections.LinkedList;


interface
   uses System.SysUtils;

type
  TDataToString = function(P: Pointer): String of object;
  TCompareData  = function(P1, P2: Pointer): NativeInt of object;

  TLinkedListNode<T> = class
  protected
    FData: T;
    FPrev,
    FNext: TLinkedListNode<T>;
  public
    constructor Create;
    procedure   ChangeEntry(const AValue: T);

    property    Data: T read FData write FData;
    property    Prev: TLinkedListNode<T> read FPrev write FPrev;
    property    Next: TLinkedListNode<T> read FNext write FNext;
  end;

  TLinkedList<T> = class
  protected
    FFirst,
    FLast        : TLinkedListNode<T>;
    FDataToString: TDataToString;
    FCompareData : TCompareData;

    function    DefaultCompareData(P1, P2: Pointer): NativeInt;
    function    GetCount: Integer;
    function    GetNode(AIndex: Integer): TLinkedListNode<T>;
    procedure   QuickSort(AList: array of TLinkedListNode<T>; L, H: Integer);
    function    Compare(const AValue1, AValue2: T): NativeInt;
  public
    constructor Create;
    destructor  Destroy; override;

    procedure   Clear; virtual;
    procedure   ClearObjects; virtual;
    function    IsEmpty: Boolean; virtual;
    procedure   AddFirst(AData: T); virtual;
    procedure   AddLast(AData: T); virtual;
    procedure   AddAfter(const ARefNode: TLinkedListNode<T>; const ANode: TLinkedListNode<T>);overload;virtual ;
    procedure   AddAfter(const ARefNode: TLinkedListNode<T>; const AValue: T); overload; virtual;
    procedure   AddBefore(const ARefNode: TLinkedListNode<T>; const ANode: TLinkedListNode<T>); overload;virtual;
    procedure   AddBefore(const ARefNode: TLinkedListNode<T>; const AValue: T); overload; virtual;
    procedure   Insert(AIndex: Integer; AData: T); virtual;
    function    DeleteFirst: T; virtual;
    function    DeleteLast: T; virtual;
    function    Delete(AIndex: Integer): T; overload; virtual;
    function    Delete(const AData: T): T; overload; virtual;
    function    FindData(AData: T): Integer; virtual;
    function    FindNode(ANode: TLinkedListNode<T>): Integer; virtual;
    procedure   Swap(ANode1, ANode2: TLinkedListNode<T>); virtual;
    procedure   Sort; virtual;

    function    ToString: String; overload; override;

    property    DataToString: TDataToString read FDataToString write FDataToString;
    property    CompareData : TCompareData  read FCompareData  write FCompareData;
    property    Count: Integer read GetCount;
    property    First: TLinkedListNode<T> read FFirst;
    property    Last : TLinkedListNode<T> read FLast;
    property    Node[AIndex: Integer]: TLinkedListNode<T> read GetNode;
  end;

  function BinaryCompare(const ALeft, ARight: Pointer; const ASize: NativeUInt): NativeInt;

implementation

function BinaryCompare(const ALeft, ARight: Pointer; const ASize: NativeUInt): NativeInt;
var
  LLPtr, LRPtr: Pointer;
  LLen: NativeUInt;
begin
  { Init }
  LLPtr := ALeft;
  LRPtr := ARight;
  LLen := ASize;
  Result := 0; // Equal!

  { Compare by NativeInts at first }
  while LLen > SizeOf(NativeInt) do
  begin
    { Compare left to right }
    if PNativeInt(LLPtr)^ > PNativeInt(LRPtr)^ then Exit(1)
    else if PNativeInt(LLPtr)^ < PNativeInt(LRPtr)^ then Exit(-1);

    Dec(LLen, SizeOf(NativeInt));
    Inc(PNativeInt(LLPtr));
    Inc(PNativeInt(LRPtr));
  end;

  { If there are bytes left to compare, use byte traversal }
  if LLen > 0 then
  begin
    while LLen > 0 do
    begin
      Result := PByte(LLPtr)^ - PByte(LRPtr)^;
      if Result <> 0 then
        Exit;

      Dec(LLen);
      Inc(PByte(LLPtr));
      Inc(PByte(LRPtr));
    end;
  end;
end;

{ TLinkedListNode }

{ ----- protected methods ----- }

{ ----- public methods ----- }

constructor TLinkedListNode<T>.Create;
begin
  inherited Create;
  FPrev:= nil;
  FNext:= nil;
  FillChar(FData, SizeOf(FData), 0);
end;

procedure  TLinkedListNode<T>.ChangeEntry(const AValue: T) ;
begin
	 FData := AValue;
end ;

{ TLinkedList }

{ ----- protected methods ----- }

function    TLinkedList<T>.DefaultCompareData(P1, P2: Pointer): NativeInt;
begin
  Result:= Integer(P2^) - Integer(P1^);
end;

function    TLinkedList<T>.GetCount: Integer;
var
  i  : Integer;
  tmp: TLinkedListNode<T>;
begin
  if NOT IsEmpty then
  begin
    Result:= 0;
    tmp   := FFirst;
    while Assigned(tmp) do
    begin
      Inc(Result);
      tmp:= tmp.Next;
    end;
  end
  else
    exit(0);
end;

function    TLinkedList<T>.GetNode(AIndex: Integer): TLinkedListNode<T>;
var
  i  : Integer;
  tmp: TLinkedListNode<T>;
begin
  if NOT IsEmpty then
  begin
    i:= 0;
    tmp:= FFirst;
    while Assigned(tmp) do
    begin
      if i = AIndex then
        exit(tmp);
      Inc(i);
      tmp:= tmp.Next;
    end;
  end
  else
    exit(nil);
end;

procedure   TLinkedList<T>.QuickSort(AList: array of TLinkedListNode<T>; L, H: Integer);
var
  i, j : Integer;
  pivot: TLinkedListNode<T>;
begin
  if L>=H then
    exit;
  pivot:= AList[(L+H) div 2];
  i:= L;
  j:= H;
  repeat
    while FCompareData(@AList[i].Data, @pivot.Data) > 0 do inc(i);
    while FCompareData(@AList[j].Data, @pivot.Data) < 0 do dec(j);
    if i<=j then
    begin
      if i<j then
        Swap(AList[i], AList[j]);
      Inc(i);
      Dec(j);
    end;
  until i>j;
  if L<=j then QuickSort(AList, L, j);
  if i<=H then QuickSort(AList, i, H);
end;

{ ----- public methods ----- }

constructor TLinkedList<T>.Create;
begin
  inherited;
  FFirst:= nil;
  FLast := nil;
  DataToString:= nil;
  CompareData := DefaultCompareData;
end;

destructor  TLinkedList<T>.Destroy;
begin
  Clear;
  inherited;
end;

function TLinkedList<T>.Compare(const AValue1, AValue2: T): NativeInt;
begin
  Result := BinaryCompare(@AValue1, @AValue2, SizeOf(T));
end;

procedure   TLinkedList<T>.Clear;
var
  tmp, tmp2: TLinkedListNode<T>;
begin
  if NOT IsEmpty then
  begin
    tmp:= FFirst;
    while Assigned(tmp) do
    begin
      tmp2:= tmp.Next;
      tmp.Free;
      tmp:= tmp2;
    end;
    FFirst := nil;
    FLast  := nil;
  end;
end;

procedure   TLinkedList<T>.ClearObjects;
var
  tmp, tmp2: TLinkedListNode<T>;
begin
  if NOT IsEmpty then
  begin
    tmp:= FFirst;
    while Assigned(tmp) do
    begin
      tmp2:= tmp.Next;
      tmp.Free;
      tmp:= tmp2;
    end;
    FFirst:= nil;
    FLast := nil;
  end;
end;

function    TLinkedList<T>.IsEmpty: Boolean;
begin
  Result:= NOT Assigned(FFirst);
end;

procedure TLinkedList<T>.AddAfter(const ARefNode: TLinkedListNode<T>; const AValue: T);
var
  tmp2: TLinkedListNode<T> ;
begin
  { Re-route }
  tmp2       := TLinkedListNode<T>.Create;
  tmp2.FData := AValue;
  AddAfter(ARefNode, tmp2);
end;

procedure TLinkedList<T>.AddAfter(const ARefNode: TLinkedListNode<T>; const ANode: TLinkedListNode<T>);
var
  Current: TLinkedListNode<T>;
begin
  if ARefNode = nil then Exit ;

  if ANode = nil then Exit  ;

  { Test for immediate value }
  if (FFirst = nil) then Exit;

  { Start value }
  Current := FFirst;

  while Current <> nil do
  begin

    if (Current = ARefNode) then
    begin
      ANode.FPrev := Current;
      ANode.FNext := Current.FNext;
      Current.FNext := ANode;

      if (ANode.FNext <> nil) then
          ANode.FNext.FPrev := ANode
      else
          FLast := ANode;

      Exit;
    end;

    Current := Current.FNext;
  end;
end;

procedure TLinkedList<T>.AddBefore(const ARefNode: TLinkedListNode<T>; const AValue: T);
var
  tmp2: TLinkedListNode<T> ;
begin
  { Re-route }
  tmp2       := TLinkedListNode<T>.Create;
  tmp2.FData := AValue;
  AddBefore(ARefNode, tmp2);
end;

procedure TLinkedList<T>.AddBefore(const ARefNode: TLinkedListNode<T>; const ANode: TLinkedListNode<T>);
var
  Current: TLinkedListNode<T>;
begin
  if ARefNode = nil then Exit ;

  if ANode = nil then Exit  ;

  { Test for immediate value }
  if (FFirst = nil) then Exit;

  { Start value }
  Current := FFirst;

  while Current <> nil do
  begin

    if (Current = ARefNode) then
    begin
      ANode.FNext := Current;
      ANode.FPrev := Current.FPrev;
      Current.FPrev := ANode;

      if ANode.FPrev <> nil then
         ANode.FPrev.FNext := ANode;

      if Current = FFirst then
         FFirst := ANode;

      Exit;
    end;

    Current := Current.FNext;
  end;
end;

procedure   TLinkedList<T>.AddFirst(AData: T);
var
  tmp: TLinkedListNode<T>;
begin
  tmp:= TLinkedListNode<T>.Create;
  tmp.Data:= AData;

  if NOT IsEmpty then
  begin
    tmp.Next   := FFirst;
    FFirst.Prev:= tmp;
    FFirst     := tmp;
  end
  else
  begin
    FFirst:= tmp;
    FLast := FFirst;
  end;
end;

procedure   TLinkedList<T>.AddLast(AData: T);
var
  tmp: TLinkedListNode<T>;
begin
  tmp:= TLinkedListNode<T>.Create;
  tmp.Data:= AData;

  if NOT IsEmpty then
  begin
    tmp.Prev  := FLast;
    FLast.Next:= tmp;
    FLast     := tmp;
  end
  else
  begin
    FFirst:= tmp;
    FLast := FFirst;
  end;
end;

procedure   TLinkedList<T>.Insert(AIndex: Integer; AData: T);
var
  i  : Integer;
  ins,
  tmp: TLinkedListNode<T>;
begin
  if NOT isEmpty then
  begin
    i:= 0;
    tmp:= FFirst;
    while Assigned(tmp) do
    begin
      if i = AIndex then
      begin
        ins:= TLinkedListNode<T>.Create;
        ins.Data:= AData;
        if NOT Assigned(tmp.Prev) then
          FFirst:= ins
        else
          tmp.Prev.Next:= ins;
        ins.Next:= tmp;
        ins.Prev:= tmp.Prev;
        tmp.Prev:= ins;
        exit;
      end;
      tmp:= tmp.Next;
      Inc(i);
    end;
  end;
end;

function    TLinkedList<T>.DeleteFirst: T;
var
  tmp: TLinkedListNode<T>;
begin
  if NOT IsEmpty then
  begin
    tmp   := FFirst;
    FFirst:= FFirst.Next;
    Result:= tmp.Data;
    tmp.Free;
    if Assigned(FFirst)  then
        FFirst.Prev:= nil ;

  end
  else
    FillChar(Result, SizeOf(Result), 0);
end;

function    TLinkedList<T>.DeleteLast: T;
var
  tmp: TLinkedListNode<T>;
begin
  if NOT IsEmpty then
  begin
    tmp   := FLast;
    FLast := FLast.Prev;
    Result:= tmp.Data;
    tmp.Free;
    FLast.Next:= nil;
  end
  else
    FillChar(Result, SizeOf(Result), 0);
end;

function    TLinkedList<T>.Delete(AIndex: Integer): T;
var
  i  : Integer;
  tmp: TLinkedListNode<T>;
begin
  if NOT IsEmpty then
  begin
    i  := 0;
    tmp:= FFirst;
    while Assigned(tmp) do
    begin
      if i = AIndex then
      begin
        if tmp <> FFirst then
          tmp.Prev.Next:= tmp.Next
        else
          exit(DeleteFirst);
        if tmp <> FLast then
          tmp.Next.Prev:= tmp.Prev
        else
          exit(DeleteLast);
        Result:= tmp.Data;
        tmp.Free;
        exit;
      end;
      Inc(i);
      tmp:= tmp.Next;
    end;
  end
  else
    FillChar(Result, SizeOf(Result), 0);
end;

function TLinkedList<T>.Delete(const AData: T): T;
var
  FoundIdx: Integer;
begin
  { Find the node }
  FoundIdx := FindData(AData);

  { Free if found }
  if (FoundIdx >= 0) then
  begin
      Result := Delete(FoundIdx)
  end;
end;

function    TLinkedList<T>.FindData(AData: T): Integer;
var
  i  : Integer;
  tmp: TLinkedListNode<T>;
begin
  Result:= -1;

  if NOT IsEmpty then
  begin
    i  := 0;
    tmp:= FFirst;
    while Assigned(tmp) do
    begin
      if Compare(tmp.Data,AData) = 0 then
        exit(i);
      Inc(i);
      tmp:= tmp.Next;
    end;
  end;
end;

function    TLinkedList<T>.FindNode(ANode: TLinkedListNode<T>): Integer;
var
  i  : Integer;
  tmp: TLinkedListNode<T>;
begin
  Result:= -1;
  if NOT IsEmpty then
  begin
    i  := 0;
    tmp:= FFirst;
    while Assigned(tmp) do
    begin
      if tmp = ANode then
        exit(i);
      Inc(i);
      tmp:= tmp.Next;
    end;
  end;
end;

procedure   TLinkedList<T>.Swap(ANode1, ANode2: TLinkedListNode<T>);
var
  tmp: T;
begin
  // quick and dirty way ;)
  tmp        := ANode1.Data;
  ANode1.Data:= ANode2.Data;
  ANode2.Data:= tmp;
end;

procedure   TLinkedList<T>.Sort;
var
  list: array of TLinkedListNode<T>;
  l   : Integer;
  tmp : TLinkedListNode<T>;
begin
  if IsEmpty then
    exit;
  tmp:= FFirst;
  while Assigned(tmp) do
  begin
    l:= Length(list);
    SetLength(list, l+1);
    list[l]:= tmp;
    tmp:= tmp.Next;
  end;
  if l < 2 then
    exit;
  QuickSort(list, 0, High(list));
  SetLength(list, 0);
end;

function    TLinkedList<T>.ToString: String;
var
  tmp: TLinkedListNode<T>;
begin
  if (NOT IsEmpty) AND (Assigned(DataToString)) then
  begin
    Result:= '[';
    tmp   := FFirst;
    while tmp <> nil do
    begin
      Result:= Result + DataToString(@tmp.Data) + ' ';
      tmp   := tmp.Next;
    end;
    SetLength(Result, Length(Result)-1);
    Result:= Result + ']';
  end
  else
    exit('[]');
end;

end.