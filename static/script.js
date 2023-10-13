function AutorefreshChecked() {
  return document.getElementById("autorefresh").checked;
}

function ToPrecision(n, precision) {
  if (n > (Math.pow(10, precision) - 1)) {
    return Math.round(n);
  } else {
    return n.toPrecision(precision);
  }
}

function FormatBytes(n) {
  if (n >= 1024 * 1024 * 1024) {
    return ToPrecision(n / 1024 / 1024 / 1024, 2) + ' GB';
  } else if (n >= 1024 * 1024) {
    return ToPrecision(n / 1024 / 1024, 2) + ' MB';
  } else if (n > 1024) {
    return ToPrecision(n / 1024, 2) + ' kB';
  } else {
    return ToPrecision(n, 2) + ' B';
  }
}

function FormatTime(ms, max_components = 2) {
  let ret = '';
  let components = 0;
  function AppendUnit(milliseconds_per_unit, unit_name_singular, unit_name_plural) {
    if (components >= max_components) {
      return;
    }
    let whole_units = Math.floor(ms / milliseconds_per_unit);
    if (whole_units) {
      ms -= whole_units * milliseconds_per_unit;
      ret += ' ' + whole_units + ' ' + (whole_units == 1 ? unit_name_singular : unit_name_plural);
      components += 1;
    }
  }
  AppendUnit(24 * 60 * 60 * 1000, 'day', 'days');
  AppendUnit(60 * 60 * 1000, 'hour', 'hours');
  AppendUnit(60 * 1000, 'minute', 'minutes');
  AppendUnit(1000, 'second', 'seconds');
  AppendUnit(1, 'ms', 'ms');
  return ret.trim();
}

function FormatTimeAgo(ms) {
  if (ms <= 0) {
    return 'now';
  } else {
    return FormatTime(ms) + ' ago';
  }
}

const N = 600;
const BarHeight = 100
const BarSpacing = 16;

// Global configuration shared by all graphs on the page.
let DayBarConfig = {
  color: '#b6b0c8',
  offset_y: BarHeight * 2 + BarSpacing * 2,
  milliseconds_length: 24 * 60 * 60 * 1000,
  focus_time: 0
};

let HourBarConfig = {
  color: '#c8b0b5',
  offset_y: BarHeight + BarSpacing,
  milliseconds_length: 60 * 60 * 1000,
  focus_time: 0,
  parent: DayBarConfig,
};

let MinuteBarConfig = {
  color: '#c8c7b0',
  offset_y: 0,
  milliseconds_length: 60 * 1000,
  parent: HourBarConfig,
};

DayBarConfig.child = HourBarConfig;
HourBarConfig.child = MinuteBarConfig;

MinuteBarConfig.EndTime = function (now) {
  if (HourBarConfig.focus_time) {
    return HourBarConfig.focus_time;
  } else {
    return now;
  }
};

HourBarConfig.EndTime = function (now) {
  if (DayBarConfig.focus_time) {
    return DayBarConfig.focus_time;
  } else {
    return now;
  }
};

DayBarConfig.EndTime = function (now) {
  return now;
};

function RenderGraph(canvas) {
  const DownColor = 'rgb(52, 202, 56)';
  const UpColor = 'rgb(255, 186, 0)';
  const FontSize = 14;
  const LineWidth = 1;

  let dpr = window.devicePixelRatio || 1;
  let H = 3 * BarHeight + 3 * BarSpacing;
  canvas.width = N * dpr;
  canvas.height = H * dpr;
  canvas.style.width = N + 'px';
  canvas.style.height = H + 'px';
  let ctx = canvas.getContext('2d', { alpha: false });
  ctx.scale(dpr, dpr);
  ctx.fillStyle = 'white';
  ctx.fillRect(0, 0, N, H);
  let datapoints = canvas.datapoints;
  let now = Date.now();

  class Series {
    constructor(symbol, color, milliseconds_length) {
      this.symbol = symbol;
      this.color = color;
      this.data = new Uint32Array(N);
      this.milliseconds_length = milliseconds_length;
      this.milliseconds_per_pixel = milliseconds_length / N;
    }
    precomputeStats() {
      this.max = this.data.reduce((a, b) => (b > a ? b : a), 0);
      this.sum = this.data.reduce((a, b) => a + b, 0);
      this.avg = this.sum / N;
    }
    static drawStatsLegend(offset_y, ctx) {
      ctx.fillStyle = 'black';
      ctx.textAlign = 'right';
      ctx.fillText('Top', LineWidth + 80, offset_y + LineWidth);
      ctx.fillText('Average', LineWidth + 150, offset_y + LineWidth);
      ctx.fillText('Total', LineWidth + 210, offset_y + LineWidth);
    }
    drawStats(offset_y, ctx) {
      ctx.fillStyle = this.color;
      ctx.textAlign = 'left';
      ctx.fillText(this.symbol, LineWidth, offset_y + LineWidth);
      ctx.textAlign = 'right';
      ctx.fillText(FormatBytes(this.max / this.milliseconds_per_pixel * 1000) + '/s', LineWidth + 80, offset_y + LineWidth);
      ctx.fillText(FormatBytes(this.avg / this.milliseconds_per_pixel * 1000) + '/s', LineWidth + 150, offset_y + LineWidth);
      ctx.fillText(FormatBytes(this.sum), LineWidth + 210, offset_y + LineWidth);
    }
  }

  class Bar {
    constructor(config) {
      this.config = config;
      this.color = config.color;
      this.offset_y = config.offset_y;
      this.milliseconds_length = config.milliseconds_length;
      this.up = new Series('⬆', UpColor, this.milliseconds_length);
      this.down = new Series('⬇', DownColor, this.milliseconds_length);
      this.milliseconds_per_pixel = this.milliseconds_length / N;
      this.end = config.EndTime(now);
    }
    addTraffic(time_up_down_arr) {
      let i = Math.floor((this.end - time_up_down_arr[0]) / this.milliseconds_per_pixel);
      if (i < 0 || i >= N) return;
      this.up.data[i] += time_up_down_arr[1];
      this.down.data[i] += time_up_down_arr[2];
    }
    precomputeStats() {
      this.up.precomputeStats();
      this.down.precomputeStats();
    }
    drawStats(ctx) {
      Series.drawStatsLegend(this.offset_y, ctx);
      this.down.drawStats(this.offset_y + FontSize, ctx);
      this.up.drawStats(this.offset_y + FontSize * 2, ctx);
    }
    drawFrame(ctx) {
      ctx.lineWidth = LineWidth;
      ctx.strokeStyle = this.color;
      ctx.fillStyle = this.color;
      ctx.strokeRect(LineWidth / 2, this.offset_y + LineWidth / 2, N - LineWidth, BarHeight - LineWidth);
      let end_time = this.config.EndTime(now);
      let start_time = end_time - this.milliseconds_length;

      let tick = new Date(end_time);
      let step = 1;
      let labelChecker = tick.getMilliseconds;
      let labelMod = 100;
      let labelFunc = function () {
        return tick.toLocaleTimeString();
      }
      if (this.milliseconds_length >= 100) {
        step *= 1000;
        tick.setMilliseconds(0);
        labelChecker = tick.getSeconds;
        labelMod = 30;
      }
      if (this.milliseconds_length >= 100 * 1000) {
        step *= 60;
        tick.setSeconds(0);
        labelChecker = tick.getMinutes;
        labelMod = 30;
        labelFunc = function () {
          return tick.toLocaleString([], { hour: 'numeric', minute: 'numeric' });
        };
      }
      if (this.milliseconds_length >= 100 * 1000 * 60) {
        step *= 60;
        tick.setMinutes(0);
        labelChecker = tick.getHours;
        labelMod = 6;
        labelFunc = function () {
          if (tick.getHours() == 0) {
            return tick.toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric' });
          } else {
            return tick.toLocaleString([], { hour: 'numeric', minute: 'numeric' });
          }
        };
      }
      if (this.milliseconds_length >= 100 * 1000 * 60 * 60) {
        step *= 24;
        tick.setHours(0);
        labelChecker = tick.getDate;
        labelMod = 7;
      }
      ctx.font = FontSize + 'px Texturina';
      ctx.textBaseline = 'top';
      ctx.textAlign = 'center';
      while (tick.getTime() > start_time) {
        let x = Math.floor((end_time - tick.getTime()) / this.milliseconds_per_pixel);
        if (x >= 0 && x < N) {
          if ((labelChecker.call(tick) % labelMod) == 0) {
            ctx.beginPath();
            ctx.moveTo(N - 1 - x, this.offset_y);
            ctx.lineTo(N - 1 - x, this.offset_y + 6);
            ctx.stroke();
            ctx.fillText(labelFunc(), N - 1 - x, this.offset_y + 6);
          } else {
            ctx.beginPath();
            ctx.moveTo(N - 1 - x, this.offset_y);
            ctx.lineTo(N - 1 - x, this.offset_y + 3);
            ctx.stroke();

          }
        }
        tick.setTime(tick.getTime() - step);
      }

      if (this.config.parent) {
        let right = N - (this.config.parent.EndTime(now) - end_time) / this.config.parent.milliseconds_length * N;
        let left = right - this.config.milliseconds_length / this.config.parent.milliseconds_length * N;
        let width = right - left;
        ctx.globalAlpha = 0.5;
        ctx.strokeRect(left + LineWidth / 2, this.config.parent.offset_y + LineWidth / 2, width - LineWidth, BarHeight - LineWidth);
        ctx.globalAlpha = 0.3;
        ctx.fillRect(left + LineWidth / 2, this.config.parent.offset_y + LineWidth / 2, width - LineWidth, BarHeight - LineWidth);
        ctx.globalAlpha = 1;
      }
      ctx.fillStyle = 'black';
      ctx.textAlign = 'left';
      ctx.fillText(FormatTimeAgo(now - start_time), 0, this.offset_y + BarHeight);
      ctx.textAlign = 'center';
      ctx.fillText('1 px = ' + FormatTime(this.milliseconds_per_pixel), N / 2, this.offset_y + BarHeight);
      ctx.textAlign = 'right';
      ctx.fillText(FormatTimeAgo(now - end_time), N - 1, this.offset_y + BarHeight);
    }
  }

  let minute = new Bar(MinuteBarConfig);
  let hour = new Bar(HourBarConfig);
  let day = new Bar(DayBarConfig);
  let bars = [day, hour, minute];

  for (let i = 0; i < datapoints.length; i++) {
    minute.addTraffic(datapoints[i]);
    hour.addTraffic(datapoints[i]);
    day.addTraffic(datapoints[i]);
  }

  bars.forEach((b) => b.precomputeStats());

  bars.forEach((b) => b.drawFrame(ctx));

  bars.forEach((b) => b.drawStats(ctx));

  ctx.globalCompositeOperation = 'multiply';
  ctx.fillStyle = DownColor;
  for (let j = 0; j < bars.length; ++j) {
    for (let i = 0; i < N; i++) {
      if (bars[j].down.data[i] >= 0) {
        let h = bars[j].down.data[i] / bars[j].down.max * BarHeight;
        ctx.fillRect(N - 1 - i, bars[j].offset_y + BarHeight - h, 1, h);
      }
    }
  }
  ctx.fillStyle = UpColor;
  for (let j = 0; j < bars.length; ++j) {
    for (let i = 0; i < N; i++) {
      if (bars[j].up.data[i] >= 0) {
        let h = bars[j].up.data[i] / bars[j].up.max * BarHeight;
        ctx.fillRect(N - 1 - i, bars[j].offset_y + BarHeight - h, 1, h);
      }
    }
  }
  ctx.globalCompositeOperation = 'source-over';

  if (typeof canvas.closed != 'undefined') {
    ctx.fillStyle = 'red';
    ctx.textAlign = 'center';
    ctx.font = 'bold 24px Texturina';
    ctx.fillText('WebSocket closed with code ' + canvas.closed, N / 2, H / 2);
  }
}

function InitGraph(canvas) {
  if (canvas.interval_id) {
    return;
  }
  canvas.datapoints = [];
  RenderGraph(canvas);
  if (canvas.dataset.ws) {
    let ws = new WebSocket(canvas.dataset.ws, "traffic");
    ws.onmessage = function (event) {
      canvas.datapoints.push(JSON.parse(event.data));
    };
    ws.onclose = function (event) {
      console.log("WebSocket closed", event);
      canvas.closed = event.code;
    };
    ws.onerror = function (event) {
      console.log("WebSocket error", event);
    };
    canvas.interval_id = setInterval(() => {
      RenderGraph(canvas);
      if (canvas.closed) {
        clearInterval(canvas.interval_id);
        canvas.interval_id = null;
      }
    }, 100);
    let UpdateDayFocus = function (x) {
      let now = Date.now();
      let focus_time = now - DayBarConfig.milliseconds_length * (N - x - 0.5) / N + HourBarConfig.milliseconds_length / 2;
      if (focus_time >= now) {
        focus_time = 0;
      }
      DayBarConfig.focus_time = focus_time;
      RenderGraph(canvas);
    }
    let UpdateHourFocus = function (x) {
      let now = Date.now();
      let focus_time = HourBarConfig.EndTime(now) - HourBarConfig.milliseconds_length * (N - x - 1) / N + MinuteBarConfig.milliseconds_length / 2;
      if (focus_time >= now) {
        focus_time = 0;
      }
      HourBarConfig.focus_time = focus_time;
      RenderGraph(canvas);
    };
    // Change mouse cursor when over graph
    canvas.addEventListener('mousemove', function (e) {
      let rect = canvas.getBoundingClientRect();
      let x = e.clientX - rect.left;
      let y = e.clientY - rect.top;
      let cursor = 'default';
      if (y >= 0 && y < BarHeight) {
        // cursor = 'grab';
      } else if (y >= BarHeight + BarSpacing && y < BarHeight * 2 + BarSpacing) {
        cursor = 'crosshair';
        if (e.buttons == 1) {
          UpdateHourFocus(x);
        }
      } else if (y >= BarHeight * 2 + BarSpacing * 2 && y < BarHeight * 3 + BarSpacing * 2) {
        cursor = 'crosshair';
        if (e.buttons == 1) {
          UpdateDayFocus(x);
        }
      }
      canvas.style.cursor = cursor;
    });
    canvas.addEventListener('mousedown', function (e) {
      let rect = canvas.getBoundingClientRect();
      let x = e.clientX - rect.left;
      let y = e.clientY - rect.top;
      if (y >= 0 && y < BarHeight) {
      } else if (y >= BarHeight + BarSpacing && y < BarHeight * 2 + BarSpacing) {
        if (e.button == 0) {
          UpdateHourFocus(x);
        }
      } else if (y >= BarHeight * 2 + BarSpacing * 2 && y < BarHeight * 3 + BarSpacing * 2) {
        if (e.button == 0) {
          UpdateDayFocus(x);
        }
      }
    });
  }
}

function InitGraphs() {
  document.body.addEventListener('htmx:load', function (evt) {
    // This event should happen when htmx adds new content to the DOM but it also seems to happen on page load.
    // The `elt` field contains the element that is loaded.
    let element = evt.detail.elt;
    element.querySelectorAll('canvas.traffic').forEach(InitGraph);
  });
}

document.addEventListener("DOMContentLoaded", InitGraphs);

// Note: Gatekeeper uses `morphdom` becasue the most recent version of htmx (1.9.2)
// does not include the built-in `idiomorph` yet. This is planned for htmx-2.
// Once htmx updates, `morphdom` can be removed.
// https://unpkg.com/htmx.org@1.9.2/dist/ext/morphdom-swap.js
htmx.defineExtension('morphdom-swap', {
  isInlineSwap: function (swapStyle) {
    return swapStyle === 'morphdom';
  },
  handleSwap: function (swapStyle, target, fragment) {
    if (swapStyle === 'morphdom') {
      if (fragment.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
        morphdom(target, fragment.firstElementChild);
        return [target];
      } else {
        morphdom(target, fragment.outerHTML);
        return [target];
      }
    }
  }
});
