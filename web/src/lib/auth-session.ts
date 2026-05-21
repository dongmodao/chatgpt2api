"use client";

import { login } from "@/lib/api";
import { clearStoredAuthSession, getStoredAuthSession, setStoredAuthSession, type StoredAuthSession } from "@/store/auth";

const AUTH_SESSION_VALIDATE_TTL_MS = 5 * 60 * 1000;

let validatedSessionCache: {
  session: StoredAuthSession | null;
  expiresAt: number;
} | null = null;
let validationPromise: Promise<StoredAuthSession | null> | null = null;

export function invalidateValidatedAuthSession() {
  validatedSessionCache = null;
  validationPromise = null;
}

export async function getValidatedAuthSession(): Promise<StoredAuthSession | null> {
  const now = Date.now();
  if (validatedSessionCache && validatedSessionCache.expiresAt > now) {
    return validatedSessionCache.session;
  }
  if (validationPromise) {
    return validationPromise;
  }

  validationPromise = validateAuthSession();
  try {
    return await validationPromise;
  } finally {
    validationPromise = null;
  }
}

async function validateAuthSession(): Promise<StoredAuthSession | null> {
  const storedSession = await getStoredAuthSession();
  if (!storedSession) {
    validatedSessionCache = null;
    return null;
  }

  try {
    const data = await login(storedSession.key);
    const nextSession: StoredAuthSession = {
      key: storedSession.key,
      role: data.role,
      subjectId: data.subject_id,
      name: data.name,
    };
    await setStoredAuthSession(nextSession);
    validatedSessionCache = {
      session: nextSession,
      expiresAt: Date.now() + AUTH_SESSION_VALIDATE_TTL_MS,
    };
    return nextSession;
  } catch {
    await clearStoredAuthSession();
    validatedSessionCache = null;
    return null;
  }
}
