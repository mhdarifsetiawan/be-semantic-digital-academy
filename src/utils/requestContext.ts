import { AsyncLocalStorage } from 'node:async_hooks';

interface Store {
    payload?: string; // Simpan semua payload sebagai string
    requestId: string;
}

const asyncLocalStorage = new AsyncLocalStorage<Store>();

export default asyncLocalStorage;
