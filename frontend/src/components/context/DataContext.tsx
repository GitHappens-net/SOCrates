import { createContext, useContext, useState, type ReactNode } from "react";

interface DataCtx {
  useMock: boolean;
  toggleMock: () => void;
}

export const DataContext = createContext<DataCtx>({ useMock: false, toggleMock: () => {} });

export function DataProvider({ children }: { children: ReactNode }) {
  const [useMock, setUseMock] = useState(false);
  return (
    <DataContext.Provider value={{ useMock, toggleMock: () => setUseMock((v) => !v) }}>
      {children}
    </DataContext.Provider>
  );
}

export function useDataMode() {
  return useContext(DataContext);
}
