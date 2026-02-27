import { useState, useCallback } from 'react'
import Cropper from 'react-easy-crop'
import type { Area } from 'react-easy-crop'
import { Button } from './button'
import { Label } from './label'
import { Slider } from './slider'
import {
    Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from './dialog'
import {
    Crop, ZoomIn, Maximize2, RotateCcw, Check, X,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface ImageEditorProps {
    open: boolean
    imageSrc: string
    onClose: () => void
    onSave: (blob: Blob, filename: string) => void
    filename?: string
}

const ASPECT_PRESETS = [
    { label: 'Free', value: 0 },
    { label: '1:1', value: 1 },
    { label: '16:9', value: 16 / 9 },
    { label: '4:3', value: 4 / 3 },
    { label: '3:2', value: 3 / 2 },
] as const

const SIZE_PRESETS = [
    { label: 'Original', maxWidth: 0 },
    { label: 'Large', maxWidth: 1920 },
    { label: 'Medium', maxWidth: 1280 },
    { label: 'Small', maxWidth: 800 },
    { label: 'Tiny', maxWidth: 400 },
] as const

function createImage(url: string): Promise<HTMLImageElement> {
    return new Promise((resolve, reject) => {
        const img = new Image()
        img.addEventListener('load', () => resolve(img))
        img.addEventListener('error', reject)
        img.crossOrigin = 'anonymous'
        img.src = url
    })
}

async function getCroppedImg(
    imageSrc: string,
    pixelCrop: Area,
    maxWidth: number,
    rotation = 0,
): Promise<Blob> {
    const image = await createImage(imageSrc)
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')!

    const radians = (rotation * Math.PI) / 180
    const sin = Math.abs(Math.sin(radians))
    const cos = Math.abs(Math.cos(radians))

    // If rotated, draw on a bigger canvas first then crop
    if (rotation !== 0) {
        const bW = image.width * cos + image.height * sin
        const bH = image.width * sin + image.height * cos
        const rotCanvas = document.createElement('canvas')
        rotCanvas.width = bW
        rotCanvas.height = bH
        const rCtx = rotCanvas.getContext('2d')!
        rCtx.translate(bW / 2, bH / 2)
        rCtx.rotate(radians)
        rCtx.drawImage(image, -image.width / 2, -image.height / 2)

        // Now crop from the rotated canvas
        let outW = pixelCrop.width
        let outH = pixelCrop.height
        if (maxWidth > 0 && outW > maxWidth) {
            const s = maxWidth / outW; outW = maxWidth; outH = Math.round(outH * s)
        }
        canvas.width = outW; canvas.height = outH
        ctx.drawImage(rotCanvas, pixelCrop.x, pixelCrop.y, pixelCrop.width, pixelCrop.height, 0, 0, outW, outH)
    } else {
        let outW = pixelCrop.width
        let outH = pixelCrop.height
        if (maxWidth > 0 && outW > maxWidth) {
            const s = maxWidth / outW; outW = maxWidth; outH = Math.round(outH * s)
        }
        canvas.width = outW; canvas.height = outH
        ctx.drawImage(image, pixelCrop.x, pixelCrop.y, pixelCrop.width, pixelCrop.height, 0, 0, outW, outH)
    }

    return new Promise((resolve, reject) => {
        canvas.toBlob(blob => {
            if (blob) resolve(blob)
            else reject(new Error('Canvas toBlob failed'))
        }, 'image/jpeg', 0.92)
    })
}

export function ImageEditor({ open, imageSrc, onClose, onSave, filename = 'image.jpg' }: ImageEditorProps) {
    const [crop, setCrop] = useState({ x: 0, y: 0 })
    const [zoom, setZoom] = useState(1)
    const [rotation, setRotation] = useState(0)
    const [croppedAreaPixels, setCroppedAreaPixels] = useState<Area | null>(null)
    const [aspect, setAspect] = useState(0)
    const [maxWidth, setMaxWidth] = useState(0)
    const [saving, setSaving] = useState(false)

    const onCropComplete = useCallback((_: Area, pixels: Area) => {
        setCroppedAreaPixels(pixels)
    }, [])

    const handleReset = useCallback(() => {
        setCrop({ x: 0, y: 0 })
        setZoom(1)
        setRotation(0)
        setAspect(0)
        setMaxWidth(0)
    }, [])

    const handleSave = useCallback(async () => {
        if (!croppedAreaPixels) return
        setSaving(true)
        try {
            const blob = await getCroppedImg(imageSrc, croppedAreaPixels, maxWidth, rotation)
            const ext = filename.split('.').pop() ?? 'jpg'
            const baseName = filename.replace(/\.[^.]+$/, '')
            onSave(blob, `${baseName}_edited.${ext}`)
        } catch {
            // silent
        } finally {
            setSaving(false)
        }
    }, [croppedAreaPixels, imageSrc, maxWidth, rotation, filename, onSave])

    const sizeInfo = croppedAreaPixels
        ? `${Math.round(croppedAreaPixels.width)}×${Math.round(croppedAreaPixels.height)}`
        : ''
    const outputInfo = maxWidth > 0 && croppedAreaPixels && croppedAreaPixels.width > maxWidth
        ? ` → ${maxWidth}px wide`
        : ''

    return (
        <Dialog open={open} onOpenChange={v => !v && onClose()}>
            <DialogContent className="max-w-3xl w-[95vw] p-0 gap-0 overflow-hidden">
                <DialogHeader className="px-4 py-3 border-b shrink-0">
                    <DialogTitle className="flex items-center gap-2 text-sm">
                        <Crop className="h-4 w-4 text-primary" />
                        Edit Image
                        {sizeInfo && (
                            <span className="text-xs font-normal text-muted-foreground ml-auto tabular-nums">
                                {sizeInfo}{outputInfo}
                            </span>
                        )}
                    </DialogTitle>
                </DialogHeader>

                {/* Crop Canvas — react-easy-crop handles all the cropping interaction */}
                <div className="relative w-full h-[50vh] min-h-[300px] max-h-[500px] bg-neutral-950">
                    <Cropper
                        image={imageSrc}
                        crop={crop}
                        zoom={zoom}
                        rotation={rotation}
                        aspect={aspect || undefined}
                        onCropChange={setCrop}
                        onZoomChange={setZoom}
                        onRotationChange={setRotation}
                        onCropComplete={onCropComplete}
                        objectFit="contain"
                        showGrid
                    />
                </div>

                {/* Controls */}
                <div className="px-4 py-3 space-y-3 border-t bg-muted/20 shrink-0">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-1">
                            <Label className="text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1">
                                <ZoomIn className="h-3 w-3" /> Zoom ({zoom.toFixed(1)}x)
                            </Label>
                            <Slider value={[zoom]} onValueChange={([v]) => setZoom(v)} min={1} max={3} step={0.05} />
                        </div>
                        <div className="space-y-1">
                            <Label className="text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1">
                                <RotateCcw className="h-3 w-3" /> Rotate ({rotation}°)
                            </Label>
                            <Slider value={[rotation]} onValueChange={([v]) => setRotation(v)} min={-180} max={180} step={1} />
                        </div>
                    </div>

                    <div className="flex flex-wrap gap-4">
                        <div className="space-y-1 flex-1 min-w-[200px]">
                            <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Aspect Ratio</Label>
                            <div className="flex gap-1 flex-wrap">
                                {ASPECT_PRESETS.map(p => (
                                    <button
                                        key={p.label}
                                        onClick={() => setAspect(p.value)}
                                        className={cn(
                                            'rounded-md border px-2.5 py-1 text-[11px] font-medium transition-all',
                                            aspect === p.value
                                                ? 'bg-primary text-primary-foreground border-primary'
                                                : 'hover:bg-muted text-muted-foreground',
                                        )}
                                    >
                                        {p.label}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <div className="space-y-1 flex-1 min-w-[200px]">
                            <Label className="text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1">
                                <Maximize2 className="h-3 w-3" /> Resize
                            </Label>
                            <div className="flex gap-1 flex-wrap">
                                {SIZE_PRESETS.map(p => (
                                    <button
                                        key={p.label}
                                        onClick={() => setMaxWidth(p.maxWidth)}
                                        className={cn(
                                            'rounded-md border px-2.5 py-1 text-[11px] font-medium transition-all',
                                            maxWidth === p.maxWidth
                                                ? 'bg-primary text-primary-foreground border-primary'
                                                : 'hover:bg-muted text-muted-foreground',
                                        )}
                                    >
                                        {p.label}
                                    </button>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                <DialogFooter className="px-4 py-2.5 border-t sm:justify-between shrink-0">
                    <Button variant="ghost" size="sm" onClick={handleReset} className="gap-1.5 text-xs">
                        <RotateCcw className="h-3.5 w-3.5" /> Reset
                    </Button>
                    <div className="flex gap-2">
                        <Button variant="outline" size="sm" onClick={onClose} className="gap-1.5 text-xs">
                            <X className="h-3.5 w-3.5" /> Cancel
                        </Button>
                        <Button size="sm" onClick={handleSave} disabled={saving} className="gap-1.5 text-xs">
                            <Check className="h-3.5 w-3.5" /> {saving ? 'Processing…' : 'Apply'}
                        </Button>
                    </div>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}
