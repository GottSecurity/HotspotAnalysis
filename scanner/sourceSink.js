"use strict";

/**
 * Nearby-line source and sink heuristic.
 * High confidence means a source and a dangerous sink sit within WINDOW lines
 * in the same file. This is not data-flow analysis. An AST pass can replace
 * this module later without changing the hotspot shape.
 */

const WINDOW = 40;

function correlate(hotspots) {
  const byFile = new Map();
  for (const hotspot of hotspots) {
    if (!byFile.has(hotspot.file)) byFile.set(hotspot.file, []);
    byFile.get(hotspot.file).push(hotspot);
  }

  for (const group of byFile.values()) {
    const sources = group.filter((item) => item.role === "source");
    for (const hotspot of group) {
      hotspot.sourceToSink = false;
      hotspot.sourcePattern = "";
      if (hotspot.role !== "sink") {
        hotspot.confidence = "Low";
        continue;
      }

      let nearest = null;
      let distance = Infinity;
      for (const source of sources) {
        const gap = Math.abs(source.line - hotspot.line);
        if (gap < distance) {
          distance = gap;
          nearest = source;
        }
      }

      if (nearest && distance <= WINDOW) {
        hotspot.confidence = "High";
        hotspot.sourceToSink = true;
        hotspot.sourcePattern = `${nearest.title} at line ${nearest.line}`;
      } else if (nearest) {
        hotspot.confidence = "Medium";
        hotspot.sourcePattern = `${nearest.title} at line ${nearest.line}`;
      } else {
        hotspot.confidence = "Low";
      }
    }
  }

  return hotspots;
}

module.exports = { correlate, WINDOW };
