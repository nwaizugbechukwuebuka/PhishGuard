/**
 * Theme Store
 * 
 * Manages application theme state using Zustand
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

const useThemeStore = create(
  persist(
    (set, get) => ({
      // State
      mode: 'light', // 'light' | 'dark'
      
      // Actions
      toggleTheme: () => {
        set((state) => ({
          mode: state.mode === 'light' ? 'dark' : 'light',
        }));
      },
      
      setTheme: (mode) => {
        set({ mode });
      },
      
      // Computed values
      isDark: () => get().mode === 'dark',
      isLight: () => get().mode === 'light',
    }),
    {
      name: 'theme-storage',
      partialize: (state) => ({
        mode: state.mode,
      }),
    }
  )
);

export { useThemeStore };