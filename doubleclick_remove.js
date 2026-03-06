/**
 * Double-click node removal for ThreatGrapher graphs.
 * Attaches directly to Plotly's event system so every click fires
 * regardless of Dash's callback deduplication.
 * Supports multiple graph elements (full + simplified).
 */
(function () {
    var DOUBLE_CLICK_MS = 400;
    var GRAPH_IDS = ['graph-display-full', 'graph-display-simple'];

    function attachHandler(gd) {
        if (!gd || !gd.on || gd._dblRemoveAttached) return;
        gd._dblRemoveAttached = true;
        gd._lastClickTime = 0;

        gd.on('plotly_click', function (evtData) {
            if (!evtData || !evtData.points || !evtData.points.length) return;

            var now = Date.now();
            var isDouble = (now - gd._lastClickTime) < DOUBLE_CLICK_MS;
            gd._lastClickTime = now;
            if (!isDouble) return;

            var pt = evtData.points[0];
            var trace = gd.data[pt.curveNumber];

            // Only act on node traces (they have markers AND are shown in legend)
            if (!trace || !trace.marker) return;
            if (trace.showlegend === false) return;

            var nx = pt.x;
            var ny = pt.y;
            var pi = pt.pointIndex;

            // Deep-clone current data so Plotly.react sees a change
            var newData = JSON.parse(JSON.stringify(gd.data));

            // 1. Remove the node point from its trace
            var nt = newData[pt.curveNumber];
            nt.x.splice(pi, 1);
            nt.y.splice(pi, 1);
            if (nt.text) nt.text.splice(pi, 1);
            if (nt.hovertext) nt.hovertext.splice(pi, 1);
            if (nt.marker && nt.marker.size && Array.isArray(nt.marker.size)) {
                nt.marker.size.splice(pi, 1);
            }

            // 2. Remove connected edges, their labels, and their arrows
            var eps = 1e-10;
            for (var i = 0; i < newData.length; i++) {
                var t = newData[i];
                if (t.mode !== 'lines' || t.showlegend !== false) continue;

                // Walk edge-line triplets [x0, x1, null, ...]
                var keptX = [], keptY = [], keptHover = [], keptIdx = [];
                var ei = 0;
                for (var j = 0; j + 2 < t.x.length; j += 3) {
                    var x0 = t.x[j], x1 = t.x[j + 1];
                    var y0 = t.y[j], y1 = t.y[j + 1];
                    var hit =
                        (Math.abs(x0 - nx) < eps && Math.abs(y0 - ny) < eps) ||
                        (Math.abs(x1 - nx) < eps && Math.abs(y1 - ny) < eps);
                    if (!hit) {
                        keptX.push(x0, x1, null);
                        keptY.push(y0, y1, null);
                        if (t.hovertext) {
                            keptHover.push(t.hovertext[j], t.hovertext[j + 1], t.hovertext[j + 2]);
                        }
                        keptIdx.push(ei);
                    }
                    ei++;
                }
                t.x = keptX;
                t.y = keptY;
                if (t.hovertext) t.hovertext = keptHover;

                // Find the paired label trace (same legendgroup, mode=text)
                if (!t.legendgroup) continue;
                for (var k = 0; k < newData.length; k++) {
                    var lt = newData[k];
                    if (lt.mode !== 'text' || lt.showlegend !== false) continue;
                    if (lt.legendgroup !== t.legendgroup) continue;

                    var nlx = [], nly = [], nlt = [];
                    for (var m = 0; m < keptIdx.length; m++) {
                        var idx = keptIdx[m];
                        if (idx < lt.x.length) {
                            nlx.push(lt.x[idx]);
                            nly.push(lt.y[idx]);
                            nlt.push(lt.text[idx]);
                        }
                    }
                    lt.x = nlx;
                    lt.y = nly;
                    lt.text = nlt;
                }

                // Find the paired arrow trace (same legendgroup, mode=markers,
                // showlegend=false, has marker.angle)
                for (var k2 = 0; k2 < newData.length; k2++) {
                    var at = newData[k2];
                    if (at.mode !== 'markers' || at.showlegend !== false) continue;
                    if (at.legendgroup !== t.legendgroup) continue;
                    if (!at.marker || !at.marker.angle) continue;

                    var nax = [], nay = [], naAngles = [];
                    var naSizes = [];
                    for (var m2 = 0; m2 < keptIdx.length; m2++) {
                        var idx2 = keptIdx[m2];
                        if (idx2 < at.x.length) {
                            nax.push(at.x[idx2]);
                            nay.push(at.y[idx2]);
                            naAngles.push(at.marker.angle[idx2]);
                            if (Array.isArray(at.marker.size)) {
                                naSizes.push(at.marker.size[idx2]);
                            }
                        }
                    }
                    at.x = nax;
                    at.y = nay;
                    at.marker.angle = naAngles;
                    if (naSizes.length > 0) {
                        at.marker.size = naSizes;
                    }
                }
            }

            // Re-render with modified data, preserving layout
            Plotly.react(gd, newData, gd.layout);
        });
    }

    function attachAll() {
        for (var i = 0; i < GRAPH_IDS.length; i++) {
            var gd = document.getElementById(GRAPH_IDS[i]);
            if (gd) attachHandler(gd);
        }
    }

    // Re-attach whenever the DOM changes (graphs are dynamically created)
    new MutationObserver(function () {
        attachAll();
    }).observe(document.body, { childList: true, subtree: true });
})();
