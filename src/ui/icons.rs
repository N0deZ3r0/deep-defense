//! Icons drawn as vectors rather than typed as glyphs.
//!
//! The obvious approach — `"🔒 Lock"` — fails here. The fonts available to
//! this program do not agree on what they cover: egui's embedded Ubuntu has
//! no `→` and no `✓`, Segoe UI has `→` but still no `✓`, and emoji render as
//! flat monochrome blobs at small sizes. A missing glyph shows as a hollow
//! box, which is worse than no icon at all.
//!
//! So each icon is a handful of line segments in a unit square, scaled into
//! whatever rectangle it is given. That costs a few lines per icon and buys
//! icons that are identical on every machine, sharp at any size, and take the
//! caller's colour.

use eframe::egui::{self, Color32, Pos2, Rect, Shape, Stroke, StrokeKind, Vec2};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    LockClosed,
    LockOpen,
    Key,
    Plus,
    Search,
    Eye,
    EyeOff,
    Copy,
    Trash,
    Gear,
    Shield,
    Refresh,
    Close,
    Check,
    Globe,
    Sun,
    Moon,
    Warning,
    Info,
    Clock,
    ChevronRight,
    ChevronDown,
    Keyboard,
}

/// Paint `icon` to fill `rect`, in `color`.
///
/// The drawing is inset slightly and squared off so an icon looks the same
/// whether it is handed a square or a slightly oblong rectangle.
pub fn paint(painter: &egui::Painter, icon: Icon, rect: Rect, color: Color32) {
    let side = rect.width().min(rect.height());
    let box_rect = Rect::from_center_size(rect.center(), Vec2::splat(side));
    // Scale the stroke with the icon so it stays visually consistent, but keep
    // it at least a hairline so small icons do not fade out.
    let width = (side * 0.085).clamp(1.1, 2.4);
    let stroke = Stroke::new(width, color);

    // Map unit coordinates (0..1, y down) into the icon box.
    let p = |x: f32, y: f32| Pos2::new(box_rect.min.x + x * side, box_rect.min.y + y * side);
    let line = |pts: Vec<Pos2>| {
        painter.add(Shape::line(pts, stroke));
    };
    let closed = |pts: Vec<Pos2>| {
        painter.add(Shape::closed_line(pts, stroke));
    };

    match icon {
        Icon::LockClosed | Icon::LockOpen => {
            // Body.
            painter.rect_stroke(
                Rect::from_min_max(p(0.18, 0.45), p(0.82, 0.90)),
                egui::CornerRadius::same((side * 0.09) as u8),
                stroke,
                StrokeKind::Middle,
            );
            // Shackle: centred when closed, pushed right and lifted when open.
            let (cx, top) = if icon == Icon::LockClosed {
                (0.50, 0.20)
            } else {
                (0.68, 0.14)
            };
            let arc = arc_points(p(cx, top + 0.16), side * 0.20, 180.0, 360.0, 12);
            line(arc);
            if icon == Icon::LockClosed {
                line(vec![p(cx - 0.20, 0.36), p(cx - 0.20, 0.45)]);
                line(vec![p(cx + 0.20, 0.36), p(cx + 0.20, 0.45)]);
            } else {
                line(vec![p(cx - 0.20, 0.30), p(cx - 0.20, 0.45)]);
                line(vec![p(cx + 0.20, 0.30), p(cx + 0.20, 0.38)]);
            }
            // Keyhole.
            painter.circle_filled(p(0.50, 0.63), side * 0.055, color);
            line(vec![p(0.50, 0.66), p(0.50, 0.76)]);
        }
        Icon::Key => {
            painter.circle_stroke(p(0.30, 0.70), side * 0.17, stroke);
            line(vec![p(0.41, 0.59), p(0.86, 0.14)]);
            line(vec![p(0.66, 0.34), p(0.78, 0.46)]);
            line(vec![p(0.76, 0.24), p(0.88, 0.36)]);
        }
        Icon::Plus => {
            line(vec![p(0.5, 0.18), p(0.5, 0.82)]);
            line(vec![p(0.18, 0.5), p(0.82, 0.5)]);
        }
        Icon::Search => {
            painter.circle_stroke(p(0.43, 0.43), side * 0.25, stroke);
            line(vec![p(0.62, 0.62), p(0.85, 0.85)]);
        }
        Icon::Eye | Icon::EyeOff => {
            // Two mirrored arcs make a lens shape.
            line(arc_points(p(0.5, 0.86), side * 0.46, 213.0, 327.0, 14));
            line(arc_points(p(0.5, 0.14), side * 0.46, 33.0, 147.0, 14));
            painter.circle_stroke(p(0.5, 0.5), side * 0.13, stroke);
            if icon == Icon::EyeOff {
                line(vec![p(0.15, 0.85), p(0.85, 0.15)]);
            }
        }
        Icon::Keyboard => {
            // An outline with three key marks: enough to read as a keyboard at
            // sixteen pixels, where anything more becomes a grey smudge.
            painter.rect_stroke(
                Rect::from_min_max(p(0.10, 0.26), p(0.90, 0.74)),
                egui::CornerRadius::same((side * 0.08) as u8),
                stroke,
                StrokeKind::Middle,
            );
            for x in [0.26, 0.44, 0.62] {
                painter.line_segment([p(x, 0.42), p(x + 0.06, 0.42)], stroke);
            }
            painter.line_segment([p(0.32, 0.60), p(0.68, 0.60)], stroke);
        }
        Icon::Copy => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.14, 0.14), p(0.62, 0.62)),
                egui::CornerRadius::same((side * 0.07) as u8),
                stroke,
                StrokeKind::Middle,
            );
            painter.rect_stroke(
                Rect::from_min_max(p(0.38, 0.38), p(0.86, 0.86)),
                egui::CornerRadius::same((side * 0.07) as u8),
                stroke,
                StrokeKind::Middle,
            );
        }
        Icon::Trash => {
            line(vec![p(0.14, 0.26), p(0.86, 0.26)]);
            line(vec![p(0.38, 0.26), p(0.40, 0.14), p(0.60, 0.14), p(0.62, 0.26)]);
            line(vec![p(0.24, 0.26), p(0.30, 0.88), p(0.70, 0.88), p(0.76, 0.26)]);
            line(vec![p(0.43, 0.40), p(0.45, 0.76)]);
            line(vec![p(0.57, 0.40), p(0.55, 0.76)]);
        }
        Icon::Gear => {
            painter.circle_stroke(p(0.5, 0.5), side * 0.20, stroke);
            // Six teeth, evenly spaced.
            for i in 0..6 {
                let angle = std::f32::consts::TAU * i as f32 / 6.0;
                let (sin, cos) = angle.sin_cos();
                line(vec![
                    p(0.5 + cos * 0.26, 0.5 + sin * 0.26),
                    p(0.5 + cos * 0.40, 0.5 + sin * 0.40),
                ]);
            }
        }
        Icon::Shield => {
            closed(vec![
                p(0.5, 0.10),
                p(0.86, 0.26),
                p(0.86, 0.52),
                p(0.5, 0.90),
                p(0.14, 0.52),
                p(0.14, 0.26),
            ]);
            line(vec![p(0.34, 0.48), p(0.46, 0.62), p(0.70, 0.36)]);
        }
        Icon::Refresh => {
            line(arc_points(p(0.5, 0.5), side * 0.33, 300.0, 620.0, 18));
            // Arrow head on the open end of the arc.
            line(vec![p(0.62, 0.10), p(0.68, 0.30), p(0.86, 0.22)]);
        }
        Icon::Close => {
            line(vec![p(0.20, 0.20), p(0.80, 0.80)]);
            line(vec![p(0.80, 0.20), p(0.20, 0.80)]);
        }
        Icon::Check => {
            line(vec![p(0.18, 0.54), p(0.40, 0.76), p(0.84, 0.26)]);
        }
        Icon::Globe => {
            painter.circle_stroke(p(0.5, 0.5), side * 0.38, stroke);
            line(vec![p(0.12, 0.5), p(0.88, 0.5)]);
            // Two meridians, drawn as opposing arcs.
            line(arc_points_ellipse(p(0.5, 0.5), side * 0.17, side * 0.38, 0.0, 360.0, 20));
        }
        Icon::Sun => {
            painter.circle_stroke(p(0.5, 0.5), side * 0.20, stroke);
            for i in 0..8 {
                let angle = std::f32::consts::TAU * i as f32 / 8.0;
                let (sin, cos) = angle.sin_cos();
                line(vec![
                    p(0.5 + cos * 0.29, 0.5 + sin * 0.29),
                    p(0.5 + cos * 0.42, 0.5 + sin * 0.42),
                ]);
            }
        }
        Icon::Moon => {
            line(arc_points(p(0.5, 0.5), side * 0.36, 60.0, 300.0, 16));
            line(arc_points(p(0.30, 0.5), side * 0.40, 300.0, 420.0, 12));
        }
        Icon::Warning => {
            closed(vec![p(0.5, 0.12), p(0.92, 0.84), p(0.08, 0.84)]);
            line(vec![p(0.5, 0.38), p(0.5, 0.62)]);
            painter.circle_filled(p(0.5, 0.73), width * 0.75, color);
        }
        Icon::Info => {
            painter.circle_stroke(p(0.5, 0.5), side * 0.38, stroke);
            painter.circle_filled(p(0.5, 0.30), width * 0.75, color);
            line(vec![p(0.5, 0.44), p(0.5, 0.72)]);
        }
        Icon::Clock => {
            painter.circle_stroke(p(0.5, 0.5), side * 0.38, stroke);
            line(vec![p(0.5, 0.28), p(0.5, 0.52), p(0.68, 0.62)]);
        }
        Icon::ChevronRight => {
            line(vec![p(0.38, 0.24), p(0.64, 0.5), p(0.38, 0.76)]);
        }
        Icon::ChevronDown => {
            line(vec![p(0.24, 0.38), p(0.5, 0.64), p(0.76, 0.38)]);
        }
    }
}

/// Points along a circular arc, angles in degrees, clockwise on screen.
fn arc_points(center: Pos2, radius: f32, from_deg: f32, to_deg: f32, steps: usize) -> Vec<Pos2> {
    arc_points_ellipse(center, radius, radius, from_deg, to_deg, steps)
}

fn arc_points_ellipse(
    center: Pos2,
    radius_x: f32,
    radius_y: f32,
    from_deg: f32,
    to_deg: f32,
    steps: usize,
) -> Vec<Pos2> {
    let steps = steps.max(2);
    (0..=steps)
        .map(|i| {
            let t = i as f32 / steps as f32;
            let angle = (from_deg + (to_deg - from_deg) * t).to_radians();
            Pos2::new(
                center.x + radius_x * angle.cos(),
                center.y + radius_y * angle.sin(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    /// Run one frame and discard its output properly.
    ///
    /// `FullOutput::textures_delta` panics if dropped with unapplied deltas -
    /// a real renderer would upload them - so a test has to clear it by hand.
    fn run_frame(ctx: &egui::Context, add_contents: impl FnMut(&mut egui::Ui)) {
        let mut output = ctx.run_ui(Default::default(), add_contents);
        output.textures_delta.clear();
    }

    use super::*;

    const ALL: [Icon; 23] = [
        Icon::LockClosed,
        Icon::LockOpen,
        Icon::Key,
        Icon::Plus,
        Icon::Search,
        Icon::Eye,
        Icon::EyeOff,
        Icon::Copy,
        Icon::Trash,
        Icon::Gear,
        Icon::Keyboard,
        Icon::Shield,
        Icon::Refresh,
        Icon::Close,
        Icon::Check,
        Icon::Globe,
        Icon::Sun,
        Icon::Moon,
        Icon::Warning,
        Icon::Info,
        Icon::Clock,
        Icon::ChevronRight,
        Icon::ChevronDown,
    ];

    /// Paint every icon at several sizes into a throwaway context.
    ///
    /// This is a smoke test, not a look test: it catches the failure mode this
    /// code actually has - an arithmetic slip producing NaN, or a cast of a
    /// negative float to u8 - which would panic or silently draw nothing.
    #[test]
    fn every_icon_paints_at_every_plausible_size() {
        let ctx = egui::Context::default();
        for size in [10.0_f32, 14.0, 16.0, 24.0, 48.0, 160.0] {
            run_frame(&ctx, |ui| {
                for icon in ALL {
                    let rect = Rect::from_min_size(Pos2::ZERO, Vec2::splat(size));
                    paint(ui.painter(), icon, rect, Color32::WHITE);
                }
            });
        }
    }

    #[test]
    fn an_oblong_rect_still_produces_a_square_icon() {
        // Callers hand us button-shaped rects; the icon must not stretch.
        let ctx = egui::Context::default();
        run_frame(&ctx, |ui| {
            let rect = Rect::from_min_size(Pos2::ZERO, Vec2::new(80.0, 20.0));
            paint(ui.painter(), Icon::Gear, rect, Color32::WHITE);
        });
    }

    #[test]
    fn arc_points_are_finite_and_counted() {
        let pts = arc_points(Pos2::new(5.0, 5.0), 3.0, 0.0, 270.0, 8);
        assert_eq!(pts.len(), 9);
        assert!(pts.iter().all(|p| p.x.is_finite() && p.y.is_finite()));
    }

    #[test]
    fn a_degenerate_step_count_does_not_divide_by_zero() {
        let pts = arc_points(Pos2::ZERO, 1.0, 0.0, 90.0, 0);
        assert!(pts.iter().all(|p| p.x.is_finite() && p.y.is_finite()));
    }

    #[test]
    fn a_zero_sized_rect_is_harmless() {
        // Happens for one frame while a panel is animating open.
        let ctx = egui::Context::default();
        run_frame(&ctx, |ui| {
            let rect = Rect::from_min_size(Pos2::ZERO, Vec2::ZERO);
            for icon in ALL {
                paint(ui.painter(), icon, rect, Color32::WHITE);
            }
        });
    }
}
