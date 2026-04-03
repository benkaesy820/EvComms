import { EventEmitter } from 'events'

/**
 * Cross-module event bus for inter-subsystem communication.
 * Decoupled from StateManager to avoid circular imports.
 */
export const clusterBus = new EventEmitter()
