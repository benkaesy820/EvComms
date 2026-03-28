class AudioService {
  private ctx: AudioContext | null = null

  private init() {
    if (!this.ctx && typeof window !== 'undefined') {
      try {
        const AudioCtx = window.AudioContext || (window as any).webkitAudioContext
        if (AudioCtx) this.ctx = new AudioCtx()
      } catch (e) {
        console.error('Web Audio API not supported', e)
      }
    }
  }

  /** Helper to play layered tones natively */
  private playTone(freq: number, type: OscillatorType, startTime: number, duration: number, vol: number = 0.5) {
    if (!this.ctx) return
    const osc = this.ctx.createOscillator()
    const gain = this.ctx.createGain()
    osc.type = type
    osc.frequency.setValueAtTime(freq, startTime)
    
    osc.connect(gain)
    gain.connect(this.ctx.destination)

    gain.gain.setValueAtTime(0, startTime)
    // Quick, punchy attack
    gain.gain.linearRampToValueAtTime(vol, startTime + 0.02)
    // Smooth natural decay
    gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration)

    osc.start(startTime)
    osc.stop(startTime + duration)
  }

  /**
   * Premium Pop: Emulates a sleek "water drop" or iOS UI click using rapid pitch descent.
   */
  playPop() {
    try {
      this.init()
      if (!this.ctx) return
      if (this.ctx.state === 'suspended') this.ctx.resume()

      const now = this.ctx.currentTime
      const osc = this.ctx.createOscillator()
      const gain = this.ctx.createGain()
      osc.connect(gain)
      gain.connect(this.ctx.destination)

      osc.type = 'sine'
      // Rapid pitch envelope creates the "thunk" / "pop" feel
      osc.frequency.setValueAtTime(800, now)
      osc.frequency.exponentialRampToValueAtTime(150, now + 0.06)

      gain.gain.setValueAtTime(0, now)
      gain.gain.linearRampToValueAtTime(0.5, now + 0.01)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08)

      osc.start(now)
      osc.stop(now + 0.08)
    } catch (e) {
      // Ignore strict auto-play policies
    }
  }

  /**
   * Rich Ding: A glass-like chime combining a fundamental frequency with a perfect fifth.
   */
  playDing() {
    try {
      this.init()
      if (!this.ctx) return
      if (this.ctx.state === 'suspended') this.ctx.resume()

      const now = this.ctx.currentTime
      // Layered frequencies (A5 and E6) for a thicker, professional chime
      this.playTone(880, 'sine', now, 0.7, 0.5)
      this.playTone(1318.51, 'sine', now, 0.6, 0.2)
    } catch (e) {}
  }

  /**
   * Announcement: A bright, elegant ascending C Major chord sweep.
   */
  playAnnouncement() {
    try {
      this.init()
      if (!this.ctx) return
      if (this.ctx.state === 'suspended') this.ctx.resume()

      const now = this.ctx.currentTime
      this.playTone(523.25, 'triangle', now, 1.0, 0.3)      // C5
      this.playTone(659.25, 'triangle', now + 0.1, 1.0, 0.3) // E5
      this.playTone(783.99, 'triangle', now + 0.2, 1.2, 0.3) // G5
    } catch (e) {}
  }

  /**
   * Success: A fast, shimmering C Major arpeggio ending on C6.
   * Gives a strong feeling of achievement / completion.
   */
  playSuccess() {
    try {
      this.init()
      if (!this.ctx) return
      if (this.ctx.state === 'suspended') this.ctx.resume()

      const now = this.ctx.currentTime
      this.playTone(523.25, 'sine', now, 0.2, 0.3)
      this.playTone(659.25, 'sine', now + 0.08, 0.2, 0.3)
      this.playTone(783.99, 'sine', now + 0.16, 0.2, 0.3)
      this.playTone(1046.50, 'sine', now + 0.24, 0.8, 0.4) // Holds longer
    } catch (e) {}
  }

  /**
   * Error: A distinct, low-pitched detuned buzz chord repeated quickly.
   */
  playError() {
    try {
      this.init()
      if (!this.ctx) return
      if (this.ctx.state === 'suspended') this.ctx.resume()

      const playBuzz = (time: number) => {
        if (!this.ctx) return
        const osc1 = this.ctx.createOscillator()
        const osc2 = this.ctx.createOscillator()
        const gain = this.ctx.createGain()
        
        osc1.connect(gain)
        osc2.connect(gain)
        gain.connect(this.ctx.destination)
        
        osc1.type = 'sawtooth'
        osc2.type = 'square'
        
        // Slightly detuned low frequencies create dissonance/urgency
        osc1.frequency.setValueAtTime(150, time)
        osc2.frequency.setValueAtTime(145, time)
        
        gain.gain.setValueAtTime(0, time)
        gain.gain.linearRampToValueAtTime(0.3, time + 0.02)
        gain.gain.exponentialRampToValueAtTime(0.001, time + 0.15)
        
        osc1.start(time)
        osc1.stop(time + 0.15)
        osc2.start(time)
        osc2.stop(time + 0.15)
      }

      const now = this.ctx.currentTime
      playBuzz(now)
      playBuzz(now + 0.18) // Double pulse
    } catch (e) {}
  }
}

export const audio = new AudioService()
