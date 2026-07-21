const mongoose = require("mongoose");
const { syncUserIndexes } = require("./db");

let indexesSynced = false;

const cached =
  global.mongooseCache || (global.mongooseCache = { conn: null, promise: null });

async function connectDB() {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    const uri = process.env.MONGODB_URI;
    if (!uri) throw new Error("MONGODB_URI is not set");

    cached.promise = mongoose
      .connect(uri, {
        bufferCommands: false,
        serverSelectionTimeoutMS: 10000,
      })
      .then(async (instance) => {
        if (!indexesSynced) {
          indexesSynced = true;
          try {
            await syncUserIndexes();
          } catch (err) {
            console.warn("User index sync warning:", err.message);
          }
        }
        return instance;
      })
      .catch((err) => {
        cached.promise = null;
        throw err;
      });
  }

  cached.conn = await cached.promise;
  return cached.conn;
}

module.exports = { connectDB };
