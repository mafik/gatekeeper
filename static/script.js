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
    return ToPrecision(n / 1024 / 1024 / 1024, 2) + ' MB';
  } else if (n >= 1024 * 1024) {
    return ToPrecision(n / 1024 / 1024, 2) + ' MB';
  } else if (n > 1024) {
    return ToPrecision(n / 1024, 2) + ' kB';
  } else {
    return ToPrecision(n, 2) + ' B';
  }
}

function FormatTime(ms) {
  let ret = '';
  function AppendUnit(milliseconds_per_unit, unit_name_singular, unit_name_plural) {
    let whole_units = Math.floor(ms / milliseconds_per_unit);
    if (whole_units) {
      ms -= whole_units * milliseconds_per_unit;
      ret += ' ' + whole_units + ' ' + (whole_units == 1 ? unit_name_singular : unit_name_plural);
    }
  }
  AppendUnit(24 * 60 * 60 * 1000, 'day', 'days');
  AppendUnit(60 * 60 * 1000, 'hour', 'hours');
  AppendUnit(60 * 1000, 'minute', 'minutes');
  AppendUnit(1000, 'second', 'seconds');
  AppendUnit(1, 'ms', 'ms');
  return ret.trim();
}

function RenderGraph(canvas) {
  const N = 600;
  const BarHeight = 100
  const BarSpacing = 16;
  const DownColor = 'rgb(52, 202, 56)';
  const UpColor = 'rgb(255, 186, 0)';
  const FontSize = 14;
  const LineWidth = 1;

  canvas.width = N;
  canvas.height = 3 * BarHeight + 3 * BarSpacing;
  let ctx = canvas.getContext('2d', { alpha: false });
  ctx.fillStyle = 'white';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
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
      ctx.fillText('Top', LineWidth + 70, offset_y + LineWidth);
      ctx.fillText('Average', LineWidth + 130, offset_y + LineWidth);
      ctx.fillText('Total', LineWidth + 190, offset_y + LineWidth);
    }
    drawStats(offset_y, ctx) {
      ctx.fillStyle = this.color;
      ctx.textAlign = 'left';
      ctx.fillText(this.symbol, LineWidth, offset_y + LineWidth);
      ctx.textAlign = 'right';
      ctx.fillText(FormatBytes(this.max / this.milliseconds_per_pixel * 1000) + '/s', LineWidth + 70, offset_y + LineWidth);
      ctx.fillText(FormatBytes(this.avg / this.milliseconds_per_pixel * 1000) + '/s', LineWidth + 130, offset_y + LineWidth);
      ctx.fillText(FormatBytes(this.sum), LineWidth + 190, offset_y + LineWidth);
    }
  }

  class Bar {
    constructor(color, offset_y, milliseconds_length) {
      this.color = color;
      this.offset_y = offset_y;
      this.milliseconds_length = milliseconds_length;
      this.up = new Series('⬆', UpColor, milliseconds_length);
      this.down = new Series('⬇', DownColor, milliseconds_length);
      this.milliseconds_per_pixel = milliseconds_length / N;
    }
    addTraffic(time_up_down_arr) {
      let i = Math.floor((now - time_up_down_arr[0]) / this.milliseconds_per_pixel);
      if (i >= N) return;
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
      ctx.font = FontSize + 'px Texturina';
      ctx.strokeStyle = this.color;
      ctx.strokeRect(LineWidth / 2, this.offset_y + LineWidth / 2, canvas.width - LineWidth, BarHeight - LineWidth);
      ctx.fillStyle = 'black';
      ctx.textBaseline = 'top';
      ctx.textAlign = 'left';
      ctx.fillText(FormatTime(this.milliseconds_length) + ' ago', 0, this.offset_y + BarHeight);
      ctx.textAlign = 'center';
      ctx.fillText('1 px = ' + FormatTime(this.milliseconds_per_pixel), canvas.width / 2, this.offset_y + BarHeight);
      ctx.textAlign = 'right';
      ctx.fillText('now', canvas.width - 1, this.offset_y + BarHeight);
    }
  }

  let minute = new Bar('#c8c7b0', 0, 60 * 1000);
  let hour = new Bar('#c8b0b5', BarHeight + BarSpacing, 60 * 60 * 1000);
  let day = new Bar('#b6b0c8', BarHeight * 2 + BarSpacing * 2, 24 * 60 * 60 * 1000);
  let bars = [minute, hour, day];

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
        ctx.fillRect(canvas.width - 1 - i, bars[j].offset_y + BarHeight - h, 1, h);
      }
    }
  }
  ctx.fillStyle = UpColor;
  for (let j = 0; j < bars.length; ++j) {
    for (let i = 0; i < N; i++) {
      if (bars[j].up.data[i] >= 0) {
        let h = bars[j].up.data[i] / bars[j].up.max * BarHeight;
        ctx.fillRect(canvas.width - 1 - i, bars[j].offset_y + BarHeight - h, 1, h);
      }
    }
  }
  ctx.globalCompositeOperation = 'source-over';
}

function Throttle(func, delay) {

  // Previously called time of the function
  let prev = 0;
  return (...args) => {
    // Current called time of the function
    let now = new Date().getTime();

    // If difference is greater than delay call
    // the function again.
    if (now - prev > delay) {
      prev = now;

      // "..." is the spread operator here 
      // returning the function with the 
      // array of arguments
      return func(...args);
    }
  }
}

function InitGraph(canvas) {
  canvas.datapoints = [];
  RenderGraph(canvas);
  if (canvas.dataset.ws) {
    let ws = new WebSocket(canvas.dataset.ws, "traffic");
    canvas.prev = 0;
    const Delay = 100;
    ws.onmessage = function (event) {
      canvas.datapoints.push(JSON.parse(event.data));
    };
    setInterval(() => {
      RenderGraph(canvas);
    }, 100);
  }
}

function InitGraphs() {
  document.querySelectorAll('canvas.traffic').forEach(InitGraph);
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