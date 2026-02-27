import type { SVGProps } from "react"
import { cn } from "@/lib/utils"

export function LeafLogo({ className, ...props }: SVGProps<SVGSVGElement>) {
    return (
        <svg
            // 1. Tightened the viewBox to crop out all empty padding.
            // This forces the leaf and text to expand and fill the container.
            viewBox="1 1 21 32"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            role="img"
            aria-label="EV Leaf Logo"
            className={cn("leaf-float", className)}
            {...props}
        >
            <title>EV Leaf Logo</title>

            <g>
                <path className="leaf-draw-1" d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 0 5.5-4.78 10-10 10Z" />
                <path className="leaf-draw-2" d="M2 21c0-3 1.85-5.36 5.08-6C9.5 14.52 12 13 13 12" />
            </g>

            <text
                // 2. Perfectly re-centered to the new viewBox math
                x="11.5" 
                y="32"
                textAnchor="middle"
                className="font-black fill-current stroke-none"
                // 3. CRITICAL FIX: Removed text-[7px] and replaced it with native SVG fontSize.
                // This guarantees the text gets bigger dynamically whenever the leaf gets bigger.
                fontSize="10"
                style={{ opacity: 0 }}
            >
                EV
                <animate 
                    attributeName="opacity" 
                    values="0;1" 
                    dur="0.5s" 
                    begin="1.2s" 
                    fill="freeze" 
                />
            </text>
        </svg>
    )
}