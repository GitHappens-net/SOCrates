import { useContext } from "react";
import { DataContext } from "@/context/DataContext";

export function useDataMode() {
  return useContext(DataContext);
}
