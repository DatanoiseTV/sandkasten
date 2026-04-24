// Renders an AppIcon.icns for the sandkasten macOS app.
//
//   swift icon/generate-icon.swift
//
// Produces ./icon/AppIcon.icns. build-app.sh copies it into the bundle.
// No external deps — uses Core Graphics + `iconutil` (system tool).

import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers
import AppKit

// ── design ─────────────────────────────────────────────────────────────
//
// A minimal, rounded-rect badge with a stylised "sandbox" — a shield over
// a grid of tiles. Native Big Sur+ corner radius (22.37% of canvas),
// subtle gradient, soft inner shadow.

func draw(size: CGFloat, scale: CGFloat) -> CGImage? {
    let w = Int(size * scale)
    let h = Int(size * scale)
    let cs = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(
        data: nil,
        width: w, height: h,
        bitsPerComponent: 8,
        bytesPerRow: 0,
        space: cs,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else { return nil }

    ctx.scaleBy(x: scale, y: scale)

    // ── rounded rect background ──
    let rect = CGRect(x: 0, y: 0, width: size, height: size)
    let radius = size * 0.2237
    let mask = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)
    ctx.addPath(mask)
    ctx.clip()

    // subtle diagonal gradient, Apple-style
    let top    = CGColor(red: 0.12, green: 0.14, blue: 0.19, alpha: 1)
    let bottom = CGColor(red: 0.04, green: 0.05, blue: 0.08, alpha: 1)
    let grad = CGGradient(colorsSpace: cs, colors: [top, bottom] as CFArray,
                          locations: [0, 1])!
    ctx.drawLinearGradient(
        grad,
        start: CGPoint(x: 0, y: size),
        end:   CGPoint(x: size, y: 0),
        options: []
    )

    // ── grid of tiles (the "sandbox") ──
    let inset = size * 0.18
    let gridRect = CGRect(
        x: inset,
        y: inset * 1.1,
        width: size - inset * 2,
        height: size - inset * 2.3
    )
    let cols = 4
    let rows = 4
    let gap = size * 0.012
    let cw = (gridRect.width - gap * CGFloat(cols - 1)) / CGFloat(cols)
    let ch = (gridRect.height - gap * CGFloat(rows - 1)) / CGFloat(rows)
    let tileRadius = size * 0.02

    ctx.setFillColor(CGColor(red: 0.17, green: 0.22, blue: 0.32, alpha: 1))
    for row in 0..<rows {
        for col in 0..<cols {
            let x = gridRect.origin.x + CGFloat(col) * (cw + gap)
            let y = gridRect.origin.y + CGFloat(row) * (ch + gap)
            let tile = CGRect(x: x, y: y, width: cw, height: ch)
            ctx.addPath(CGPath(roundedRect: tile, cornerWidth: tileRadius,
                               cornerHeight: tileRadius, transform: nil))
        }
    }
    ctx.fillPath()

    // ── shield overlay, centred ──
    let shieldW = size * 0.52
    let shieldH = size * 0.62
    let sx = (size - shieldW) / 2
    let sy = (size - shieldH) / 2 - size * 0.02
    let shield = shieldPath(in: CGRect(x: sx, y: sy, width: shieldW, height: shieldH))

    // soft drop shadow for depth
    ctx.saveGState()
    ctx.setShadow(
        offset: CGSize(width: 0, height: -size * 0.02),
        blur: size * 0.06,
        color: CGColor(red: 0, green: 0, blue: 0, alpha: 0.45)
    )
    ctx.addPath(shield)
    ctx.setFillColor(CGColor(red: 0.48, green: 0.78, blue: 1.0, alpha: 1))
    ctx.fillPath()
    ctx.restoreGState()

    // shield gradient highlight
    ctx.saveGState()
    ctx.addPath(shield)
    ctx.clip()
    let hl = CGGradient(colorsSpace: cs,
                        colors: [
                            CGColor(red: 0.68, green: 0.88, blue: 1.0, alpha: 1),
                            CGColor(red: 0.32, green: 0.60, blue: 0.98, alpha: 1)
                        ] as CFArray,
                        locations: [0, 1])!
    ctx.drawLinearGradient(
        hl,
        start: CGPoint(x: sx + shieldW / 2, y: sy + shieldH),
        end:   CGPoint(x: sx + shieldW / 2, y: sy),
        options: []
    )
    ctx.restoreGState()

    // tick mark inside the shield
    ctx.saveGState()
    ctx.setStrokeColor(CGColor(red: 0.04, green: 0.07, blue: 0.13, alpha: 1))
    ctx.setLineWidth(size * 0.045)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    let cx = sx + shieldW / 2
    let cy = sy + shieldH / 2
    let unit = shieldW * 0.14
    ctx.move(to: CGPoint(x: cx - unit * 1.4, y: cy + unit * 0.1))
    ctx.addLine(to: CGPoint(x: cx - unit * 0.2, y: cy - unit * 1.1))
    ctx.addLine(to: CGPoint(x: cx + unit * 1.5, y: cy + unit * 1.2))
    ctx.strokePath()
    ctx.restoreGState()

    return ctx.makeImage()
}

func shieldPath(in rect: CGRect) -> CGPath {
    let p = CGMutablePath()
    let w = rect.width
    let h = rect.height
    let x = rect.origin.x
    let y = rect.origin.y
    // Classic heraldic shield: flat top, curved flanks, pointed bottom.
    p.move(to:        CGPoint(x: x,             y: y + h * 0.8))
    p.addQuadCurve(to: CGPoint(x: x + w * 0.5,   y: y),
                   control:  CGPoint(x: x + w * 0.02, y: y + h * 0.15))
    p.addQuadCurve(to: CGPoint(x: x + w,         y: y + h * 0.8),
                   control:  CGPoint(x: x + w * 0.98, y: y + h * 0.15))
    p.addQuadCurve(to: CGPoint(x: x + w * 0.5,   y: y + h),
                   control:  CGPoint(x: x + w * 0.75, y: y + h * 0.98))
    p.addQuadCurve(to: CGPoint(x: x,             y: y + h * 0.8),
                   control:  CGPoint(x: x + w * 0.25, y: y + h * 0.98))
    p.closeSubpath()
    return p
}

func writePNG(_ image: CGImage, to path: String) throws {
    let url = URL(fileURLWithPath: path)
    guard let dst = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)
    else { throw NSError(domain: "icon", code: 1) }
    CGImageDestinationAddImage(dst, image, nil)
    guard CGImageDestinationFinalize(dst) else {
        throw NSError(domain: "icon", code: 2)
    }
}

// ── main ───────────────────────────────────────────────────────────────

let here = URL(fileURLWithPath: #file).deletingLastPathComponent()
let iconset = here.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

struct Variant { let size: CGFloat; let scale: CGFloat; let name: String }
let variants: [Variant] = [
    Variant(size: 16,  scale: 1, name: "icon_16x16.png"),
    Variant(size: 16,  scale: 2, name: "icon_16x16@2x.png"),
    Variant(size: 32,  scale: 1, name: "icon_32x32.png"),
    Variant(size: 32,  scale: 2, name: "icon_32x32@2x.png"),
    Variant(size: 128, scale: 1, name: "icon_128x128.png"),
    Variant(size: 128, scale: 2, name: "icon_128x128@2x.png"),
    Variant(size: 256, scale: 1, name: "icon_256x256.png"),
    Variant(size: 256, scale: 2, name: "icon_256x256@2x.png"),
    Variant(size: 512, scale: 1, name: "icon_512x512.png"),
    Variant(size: 512, scale: 2, name: "icon_512x512@2x.png"),
]

for v in variants {
    guard let img = draw(size: v.size, scale: v.scale) else {
        FileHandle.standardError.write("failed to render \(v.name)\n".data(using: .utf8)!)
        exit(1)
    }
    let out = iconset.appendingPathComponent(v.name).path
    try writePNG(img, to: out)
    print("  ✓ \(v.name) (\(Int(v.size * v.scale))×\(Int(v.size * v.scale)))")
}

// iconutil pack
let proc = Process()
proc.launchPath = "/usr/bin/iconutil"
proc.arguments = ["-c", "icns", iconset.path, "-o", here.appendingPathComponent("AppIcon.icns").path]
try proc.run()
proc.waitUntilExit()
guard proc.terminationStatus == 0 else {
    FileHandle.standardError.write("iconutil failed\n".data(using: .utf8)!)
    exit(1)
}

print("\n✓ wrote \(here.appendingPathComponent("AppIcon.icns").path)")
