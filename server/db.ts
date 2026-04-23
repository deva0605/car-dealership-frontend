import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { InsertUser, users, bookings, Booking, InsertBooking } from "../drizzle/schema";
import { ENV } from './_core/env';
import { encrypt, decrypt, validateEncryptionKey } from './utils/encryption';

// Validate encryption key at module load time
validateEncryptionKey();

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

/**
 * Creates a new booking with encrypted customer PII fields.
 * customerName, customerContact, and customerId are encrypted before insertion.
 */
export async function createBooking(data: InsertBooking): Promise<Booking | null> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot create booking: database not available");
    return null;
  }

  try {
    // Encrypt sensitive fields before database insertion
    const encryptedData: InsertBooking = {
      ...data,
      customerName: encrypt(data.customerName),
      customerContact: encrypt(data.customerContact),
      customerId: encrypt(data.customerId),
    };

    const result = await db.insert(bookings).values(encryptedData);
    
    // Fetch and return the created booking with decrypted fields
    if (result && 'insertId' in result) {
      const created = await db.select().from(bookings).where(eq(bookings.id, Number(result.insertId))).limit(1);
      if (created.length > 0) {
        return decryptBooking(created[0]);
      }
    }
    return null;
  } catch (error) {
    console.error("[Database] Failed to create booking:", error);
    throw error;
  }
}

/**
 * Retrieves all bookings with decrypted customer PII fields.
 */
export async function listBookings(): Promise<Booking[]> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot list bookings: database not available");
    return [];
  }

  try {
    const results = await db.select().from(bookings);
    // Decrypt sensitive fields for each booking
    return results.map(booking => decryptBooking(booking));
  } catch (error) {
    console.error("[Database] Failed to list bookings:", error);
    throw error;
  }
}

/**
 * Retrieves a single booking by ID with decrypted customer PII fields.
 */
export async function getBookingById(id: number): Promise<Booking | null> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get booking: database not available");
    return null;
  }

  try {
    const result = await db.select().from(bookings).where(eq(bookings.id, id)).limit(1);
    if (result.length > 0) {
      return decryptBooking(result[0]);
    }
    return null;
  } catch (error) {
    console.error("[Database] Failed to get booking:", error);
    throw error;
  }
}

/**
 * Retrieves booking statistics with decrypted customer PII fields.
 */
export async function getBookingStats(): Promise<{ totalBookings: number; totalRevenue: number; bookingsByStatus: Record<string, number> } | null> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get booking stats: database not available");
    return null;
  }

  try {
    const results = await db.select().from(bookings);
    
    const totalBookings = results.length;
    const totalRevenue = results.reduce((sum, booking) => sum + booking.amount, 0);
    const bookingsByStatus: Record<string, number> = {};
    
    results.forEach(booking => {
      bookingsByStatus[booking.status] = (bookingsByStatus[booking.status] || 0) + 1;
    });
    
    return {
      totalBookings,
      totalRevenue,
      bookingsByStatus,
    };
  } catch (error) {
    console.error("[Database] Failed to get booking stats:", error);
    throw error;
  }
}

/**
 * Retrieves monthly sales revenue (aggregated, no PII fields).
 */
export async function getMonthlySalesRevenue(): Promise<{ month: string; revenue: number }[] | null> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get monthly sales revenue: database not available");
    return null;
  }

  try {
    const results = await db.select().from(bookings);
    
    const monthlyRevenue: Record<string, number> = {};
    results.forEach(booking => {
      const month = new Date(booking.createdAt).toISOString().slice(0, 7); // YYYY-MM
      monthlyRevenue[month] = (monthlyRevenue[month] || 0) + booking.amount;
    });
    
    return Object.entries(monthlyRevenue)
      .map(([month, revenue]) => ({ month, revenue }))
      .sort((a, b) => a.month.localeCompare(b.month));
  } catch (error) {
    console.error("[Database] Failed to get monthly sales revenue:", error);
    throw error;
  }
}

/**
 * Retrieves maintenance costs (aggregated, no PII fields).
 */
export async function getMaintenanceCosts(): Promise<{ month: string; cost: number }[] | null> {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get maintenance costs: database not available");
    return null;
  }

  try {
    const results = await db.select().from(bookings).where(eq(bookings.transactionType, 'service'));
    
    const monthlyCosts: Record<string, number> = {};
    results.forEach(booking => {
      const month = new Date(booking.createdAt).toISOString().slice(0, 7); // YYYY-MM
      monthlyCosts[month] = (monthlyCosts[month] || 0) + booking.amount;
    });
    
    return Object.entries(monthlyCosts)
      .map(([month, cost]) => ({ month, cost }))
      .sort((a, b) => a.month.localeCompare(b.month));
  } catch (error) {
    console.error("[Database] Failed to get maintenance costs:", error);
    throw error;
  }
}

/**
 * Helper function to decrypt sensitive fields in a booking.
 */
function decryptBooking(booking: Booking): Booking {
  return {
    ...booking,
    customerName: decrypt(booking.customerName),
    customerContact: decrypt(booking.customerContact),
    customerId: decrypt(booking.customerId),
  };
}
