// Synthesized UI sounds via Web Audio API.
// No files, no network requests, no preloading — sounds generated on demand.

type OscType = OscillatorType

interface Tone {
  freq: number
  type: OscType
  duration: number
  gainStart: number
  gainEnd: number
  startDelay?: number
}

class AudioService {
  private ctx: AudioContext | null = null
  private volume = 0.5

  private getCtx(): AudioContext | null {
    if (typeof window === 'undefined') return null
    if (!this.ctx) {
      try {
        this.ctx = new AudioContext()
      } catch {
        return null
      }
    }
    // Resume if suspended (browser autoplay policy)
    if (this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {})
    }
    return this.ctx
  }

  private playTones(tones: Tone[]) {
    const ctx = this.getCtx()
    if (!ctx) return

    for (const tone of tones) {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      const now = ctx.currentTime + (tone.startDelay ?? 0)

      osc.type = tone.type
      osc.frequency.setValueAtTime(tone.freq, now)

      gain.gain.setValueAtTime(tone.gainStart * this.volume, now)
      gain.gain.exponentialRampToValueAtTime(
        Math.max(0.0001, tone.gainEnd * this.volume),
        now + tone.duration
      )

      osc.connect(gain)
      gain.connect(ctx.destination)
      osc.start(now)
      osc.stop(now + tone.duration)
    }
  }

  // Soft bubble — incoming message while focused on chat
  playPop() {
    this.playTones([{
      freq: 880,
      type: 'sine',
      duration: 0.12,
      gainStart: 0.35,
      gainEnd: 0.001,
    }])
  }

  // Clear chime — new message in background / notification
  playDing() {
    this.playTones([
      { freq: 1047, type: 'sine', duration: 0.35, gainStart: 0.4,  gainEnd: 0.001, startDelay: 0 },
      { freq: 1319, type: 'sine', duration: 0.25, gainStart: 0.25, gainEnd: 0.001, startDelay: 0.1 },
    ])
  }

  // Ascending two-tone — account approved / action succeeded
  playSuccess() {
    this.playTones([
      { freq: 523,  type: 'sine', duration: 0.18, gainStart: 0.35, gainEnd: 0.001, startDelay: 0 },
      { freq: 784,  type: 'sine', duration: 0.22, gainStart: 0.35, gainEnd: 0.001, startDelay: 0.15 },
    ])
  }

  // Low descending thud — error / session revoked / force logout
  playError() {
    this.playTones([
      { freq: 220, type: 'triangle', duration: 0.25, gainStart: 0.5,  gainEnd: 0.001, startDelay: 0 },
      { freq: 180, type: 'triangle', duration: 0.2,  gainStart: 0.35, gainEnd: 0.001, startDelay: 0.1 },
    ])
  }

  // Announcement — three-tone ascending chime
  playAnnouncement() {
    this.playTones([
      { freq: 880,  type: 'sine', duration: 0.3,  gainStart: 0.35, gainEnd: 0.001, startDelay: 0 },
      { freq: 1047, type: 'sine', duration: 0.3,  gainStart: 0.3,  gainEnd: 0.001, startDelay: 0.08 },
      { freq: 1319, type: 'sine', duration: 0.25, gainStart: 0.2,  gainEnd: 0.001, startDelay: 0.18 },
    ])
  }
}

export const audio = new AudioService()
