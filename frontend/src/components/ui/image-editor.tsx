import { useState, useCallback, useRef } from 'react'
import ReactCrop, { centerCrop, makeAspectCrop, type Crop, type PixelCrop } from 'react-image-crop'
import 'react-image-crop/dist/ReactCrop.css'
import { Button } from './button'
import { Label } from './label'
import {
    Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from './dialog'
import {
    Crop as CropIcon, Maximize2, RotateCcw, Check, X,
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
    { label: 'Free', value: undefined },
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

function centerAspectCrop(mediaWidth: number, mediaHeight: number, aspect: number) {
    return centerCrop(
        makeAspectCrop({ unit: '%', width: 90 }, aspect, mediaWidth, mediaHeight),
        mediaWidth,
        mediaHeight
    )
}

async function getCroppedImg(
    image: HTMLImageElement,
    pixelCrop: PixelCrop,
    maxWidth: number,
): Promise<Blob> {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')

    if (!ctx) {
        throw new Error('No 2d context')
    }

    const scaleX = image.naturalWidth / image.width
    const scaleY = image.naturalHeight / image.height

    // PixelCrop values are relative to the DOM image size, so we scale it back to natural coordinates
    const srcX = pixelCrop.x * scaleX
    const srcY = pixelCrop.y * scaleY
    const srcW = pixelCrop.width * scaleX
    const srcH = pixelCrop.height * scaleY

    let outW = srcW
    let outH = srcH

    if (maxWidth > 0 && outW > maxWidth) {
        const s = maxWidth / outW
        outW = maxWidth
        outH = Math.round(outH * s)
    }

    canvas.width = outW
    canvas.height = outH

    ctx.imageSmoothingQuality = 'high'
    ctx.drawImage(
        image,
        srcX, srcY, srcW, srcH,
        0, 0, outW, outH
    )

    return new Promise((resolve, reject) => {
        canvas.toBlob(blob => {
            if (blob) resolve(blob)
            else reject(new Error('Canvas is empty'))
        }, 'image/jpeg', 0.92)
    })
}

export function ImageEditor({ open, imageSrc, onClose, onSave, filename = 'image.jpg' }: ImageEditorProps) {
    const [crop, setCrop] = useState<Crop>()
    const [completedCrop, setCompletedCrop] = useState<PixelCrop>()
    const [aspect, setAspect] = useState<number | undefined>(undefined)
    const [maxWidth, setMaxWidth] = useState(0)
    const [saving, setSaving] = useState(false)
    const imgRef = useRef<HTMLImageElement>(null)

    const handleImageLoad = (e: React.SyntheticEvent<HTMLImageElement>) => {
        const { width, height } = e.currentTarget
        if (aspect) {
            setCrop(centerAspectCrop(width, height, aspect))
        } else {
            // Default 90% crop
            setCrop({
                unit: '%',
                width: 90,
                height: 90,
                x: 5,
                y: 5
            })
        }
    }

    const handleAspectChange = (newAspect: number | undefined) => {
        setAspect(newAspect)
        if (imgRef.current) {
            if (newAspect) {
                setCrop(centerAspectCrop(imgRef.current.width, imgRef.current.height, newAspect))
            } else {
                setCrop(undefined) // Free crop
            }
        }
    }

    const handleReset = useCallback(() => {
        setCrop(undefined)
        setCompletedCrop(undefined)
        setAspect(undefined)
        setMaxWidth(0)
        if (imgRef.current) {
            setCrop({
                unit: '%',
                width: 90, height: 90, x: 5, y: 5
            })
        }
    }, [])

    const handleSave = useCallback(async () => {
        if (!completedCrop || !imgRef.current) return
        setSaving(true)
        try {
            const blob = await getCroppedImg(imgRef.current, completedCrop, maxWidth)
            const ext = filename.split('.').pop() ?? 'jpg'
            const baseName = filename.replace(/\.[^.]+$/, '')
            onSave(blob, `${baseName}_edited.${ext}`)
        } catch {
            // silent
        } finally {
            setSaving(false)
        }
    }, [completedCrop, maxWidth, filename, onSave])

    const sizeInfo = completedCrop
        ? `${Math.round(completedCrop.width)}×${Math.round(completedCrop.height)}`
        : ''
    const outputInfo = maxWidth > 0 && completedCrop && completedCrop.width > maxWidth
        ? ` → ${maxWidth}px wide`
        : ''

    return (
        <Dialog open={open} onOpenChange={v => !v && onClose()}>
            <DialogContent className="max-w-4xl w-[95vw] p-0 gap-0 overflow-hidden bg-background">
                <DialogHeader className="px-4 py-3 border-b shrink-0">
                    <DialogTitle className="flex items-center gap-2 text-sm">
                        <CropIcon className="h-4 w-4 text-primary" />
                        Edit Image
                        {sizeInfo && (
                            <span className="text-xs font-normal text-muted-foreground ml-auto tabular-nums">
                                {sizeInfo}{outputInfo}
                            </span>
                        )}
                    </DialogTitle>
                </DialogHeader>

                <div className="flex flex-col lg:flex-row max-h-[75vh]">
                    {/* Crop Canvas */}
                    <div className="flex-1 overflow-auto bg-neutral-900/10 dark:bg-neutral-950 flex items-center justify-center p-4 min-h-[300px]">
                        <ReactCrop
                            crop={crop}
                            onChange={(_, percentCrop) => setCrop(percentCrop)}
                            onComplete={(c) => setCompletedCrop(c)}
                            aspect={aspect}
                            className="max-h-full mx-auto shadow-2xl rounded-xl overflow-hidden ring-1 ring-border/50"
                        >
                            <img
                                ref={imgRef}
                                src={imageSrc}
                                alt="Crop me"
                                className="max-h-[60vh] object-contain w-auto block select-none"
                                onLoad={handleImageLoad}
                                crossOrigin="anonymous"
                            />
                        </ReactCrop>
                    </div>

                    {/* Controls Sidebar */}
                    <div className="w-full lg:w-72 border-t lg:border-t-0 lg:border-l bg-muted/10 shrink-0 flex flex-col p-4 space-y-5 overflow-y-auto max-h-[40vh] lg:max-h-none">
                        <div className="space-y-2">
                            <Label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Aspect Ratio</Label>
                            <div className="grid grid-cols-3 sm:grid-cols-2 lg:grid-cols-2 gap-2">
                                {ASPECT_PRESETS.map(p => (
                                    <button
                                        key={p.label}
                                        onClick={() => handleAspectChange(p.value)}
                                        className={cn(
                                            'rounded-lg border px-3 py-2.5 text-xs font-semibold transition-all shadow-sm min-h-[40px]',
                                            aspect === p.value
                                                ? 'bg-primary text-primary-foreground border-primary scale-[1.02]'
                                                : 'bg-background hover:bg-muted text-muted-foreground hover:text-foreground',
                                        )}
                                    >
                                        {p.label}
                                    </button>
                                ))}
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                                <Maximize2 className="h-3.5 w-3.5" /> Max Width Output
                            </Label>
                            <div className="grid grid-cols-3 sm:grid-cols-2 lg:grid-cols-2 gap-2">
                                {SIZE_PRESETS.map(p => (
                                    <button
                                        key={p.label}
                                        onClick={() => setMaxWidth(p.maxWidth)}
                                        className={cn(
                                            'rounded-lg border px-3 py-2.5 text-xs font-semibold transition-all shadow-sm min-h-[40px]',
                                            maxWidth === p.maxWidth
                                                ? 'bg-primary text-primary-foreground border-primary scale-[1.02]'
                                                : 'bg-background hover:bg-muted text-muted-foreground hover:text-foreground',
                                        )}
                                    >
                                        {p.label}
                                    </button>
                                ))}
                            </div>
                        </div>

                        <div className="mt-auto pt-4 flex-col gap-2 flex">
                            <Button variant="ghost" onClick={handleReset} className="w-full gap-2 opacity-70 hover:opacity-100">
                                <RotateCcw className="h-4 w-4" /> Reset Crop
                            </Button>
                        </div>
                    </div>
                </div>

                <DialogFooter className="px-4 sm:px-5 py-3 sm:py-4 border-t bg-muted/20 shrink-0">
                    <div className="flex flex-col-reverse sm:flex-row gap-2 w-full sm:justify-end">
                        <Button variant="outline" onClick={onClose} className="gap-2 w-full sm:w-auto">
                            <X className="h-4 w-4" /> Cancel
                        </Button>
                        <Button onClick={handleSave} disabled={saving || !completedCrop} className="gap-2 px-6 w-full sm:w-auto">
                            <Check className="h-4 w-4" /> {saving ? 'Saving...' : 'Save'}
                        </Button>
                    </div>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}
