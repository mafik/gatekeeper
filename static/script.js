function AutorefreshChecked() {
  return document.getElementById("autorefresh").checked;
}

function RenderGraphs() {
  document.querySelectorAll('canvas.traffic').forEach(function (canvas) {
    let n = 600;
    canvas.width = n;
    const BarHeight = 100
    const BarSpacing = 10;
    canvas.height = 3 * BarHeight + 3 * BarSpacing;
    let ctx = canvas.getContext('2d', { alpha: false });
    ctx.fillStyle = 'white';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    let datapoints_json = canvas.innerHTML;
    let datapoints = JSON.parse(datapoints_json);
    let now = Date.now();

    let minute_up = new Uint32Array(n);
    let minute_down = new Uint32Array(n);
    let hour_up = new Uint32Array(n);
    let hour_down = new Uint32Array(n);
    let day_up = new Uint32Array(n);
    let day_down = new Uint32Array(n);

    for (let i = 0; i < datapoints.length; i++) {
      let [time, up, down] = datapoints[i];
      let i_minute = Math.floor((now - time) / (100));
      let i_hour = Math.floor(i_minute / 60);
      let i_day = Math.floor(i_hour / 24);
      if (i_minute < minute_down.length) {
        minute_up[i_minute] += up;
        minute_down[i_minute] += down;
      }
      if (i_hour < hour_down.length) {
        hour_up[i_hour] += up;
        hour_down[i_hour] += down;
      }
      if (i_day < day_down.length) {
        day_up[i_day] += up;
        day_down[i_day] += down;
      }
    }

    let minute_up_max = 0, minute_down_max = 0, hour_up_max = 0, hour_down_max = 0, day_up_max = 0, day_down_max = 0;

    for (let i = 0; i < n; i++) {
      minute_up_max = Math.max(minute_up_max, minute_up[i]);
      minute_down_max = Math.max(minute_down_max, minute_down[i]);
      hour_up_max = Math.max(hour_up_max, hour_up[i]);
      hour_down_max = Math.max(hour_down_max, hour_down[i]);
      day_up_max = Math.max(day_up_max, day_up[i]);
      day_down_max = Math.max(day_down_max, day_down[i]);
    }

    ctx.lineWidth = 2;
    ctx.strokeStyle = '#b6b0c8';
    ctx.strokeRect(1, BarHeight * 2 + BarSpacing * 2 + 1, canvas.width - 2, BarHeight - 2);

    ctx.translate(0, BarHeight + BarSpacing);

    ctx.fillStyle = '#f8e0e5';
    ctx.beginPath();
    ctx.moveTo(canvas.width, BarHeight + BarSpacing);
    ctx.lineTo(canvas.width - 10, BarHeight + BarSpacing);
    ctx.bezierCurveTo(canvas.width - 10, BarHeight, 0, BarHeight + BarSpacing, 0, BarHeight);
    ctx.lineTo(canvas.width, BarHeight);
    ctx.closePath();
    ctx.fill();

    ctx.strokeStyle = '#c8b0b5';
    ctx.strokeRect(1, 1, canvas.width - 2, BarHeight - 2);
    ctx.strokeRect(canvas.width - 10 + 1, BarHeight + BarSpacing + 1, 10 - 2, BarHeight - 2);

    ctx.translate(0, -BarHeight - BarSpacing);

    ctx.fillStyle = '#f8f7e0';
    ctx.beginPath();
    ctx.moveTo(canvas.width, BarHeight + BarSpacing);
    ctx.lineTo(canvas.width - 10, BarHeight + BarSpacing);
    ctx.bezierCurveTo(canvas.width - 10, BarHeight, 0, BarHeight + BarSpacing, 0, BarHeight);
    ctx.lineTo(canvas.width, BarHeight);
    ctx.closePath();
    ctx.fill();

    ctx.strokeStyle = '#c8c7b0';
    ctx.lineWidth = 2;
    ctx.strokeRect(1, 1, canvas.width - 2, BarHeight - 2);
    ctx.strokeRect(canvas.width - 10 + 1, BarHeight + BarSpacing + 1, 10 - 2, BarHeight - 2);

    ctx.font = '10px Texturina';
    ctx.fillStyle = 'rgb(0, 0, 0)';
    ctx.textBaseline = 'top';
    ctx.fillText('1 minute ago', 0, BarHeight);
    ctx.fillText('1 hour ago', 0, 2 * BarHeight + BarSpacing);
    ctx.fillText('1 day ago', 0, 3 * BarHeight + 2 * BarSpacing);
    ctx.textAlign = 'right';
    ctx.fillText('now', canvas.width - 1, BarHeight);
    ctx.fillText('now', canvas.width - 1, 2 * BarHeight + BarSpacing);
    ctx.fillText('now', canvas.width - 1, 3 * BarHeight + 2 * BarSpacing);

    const DownColor = '#31962d';
    const UpColor = '#91762c';
    ctx.fillStyle = DownColor;
    ctx.textAlign = 'left';
    ctx.fillText('max ⬇ = ' + Math.round(minute_down_max * 10) + ' B/s', 2, 2);
    ctx.fillText('max ⬇ = ' + Math.round(hour_down_max * 10 / 60) + ' B/s', 2, 2 + BarHeight + BarSpacing);
    ctx.fillText('max ⬇ = ' + Math.round(day_down_max * 10 / 60 / 24) + ' B/s', 2, 2 + BarHeight * 2 + BarSpacing * 2);
    ctx.fillStyle = UpColor;
    ctx.fillText('max ⬆ = ' + Math.round(minute_up_max * 10) + ' B/s', 2, 12);
    ctx.fillText('max ⬆ = ' + Math.round(hour_up_max * 10 / 60) + ' B/s', 2, 12 + BarHeight + BarSpacing);
    ctx.fillText('max ⬆ = ' + Math.round(day_up_max * 10 / 60 / 24) + ' B/s', 2, 12 + BarHeight * 2 + BarSpacing * 2);


    ctx.globalCompositeOperation = 'multiply';
    ctx.fillStyle = DownColor;
    for (let i = 0; i < n; i++) {
      if (minute_down[i] >= 0) {
        let h = minute_down[i] / minute_down_max * BarHeight;
        ctx.fillRect(canvas.width - 1 - i, BarHeight - h, 1, h);
      }
      if (hour_down[i] >= 0) {
        let h = hour_down[i] / hour_down_max * BarHeight;
        ctx.fillRect(canvas.width - 1 - i, 2 * BarHeight + BarSpacing - h, 1, h);
      }
      if (day_down[i] >= 0) {
        let h = day_down[i] / day_down_max * BarHeight;
        ctx.fillRect(canvas.width - 1 - i, 3 * BarHeight + 2 * BarSpacing - h, 1, h);
      }
    }
    ctx.fillStyle = UpColor;
    for (let i = 0; i < n; i++) {
      if (minute_up[i] >= 0) {
        let h = minute_up[i] / minute_up_max * BarHeight;
        ctx.fillRect(canvas.width - 1 - i, BarHeight - h, 1, h);
      }
      if (hour_up[i] >= 0) {
        let h = hour_up[i] / hour_up_max * BarHeight;
        ctx.fillRect(canvas.width - 1 - i, 2 * BarHeight + BarSpacing - h, 1, h);
      }
      if (day_up[i] >= 0) {
        let h = day_up[i] / day_up_max * BarHeight;
        ctx.fillRect(canvas.width - 1 - i, 3 * BarHeight + 2 * BarSpacing - h, 1, h);
      }
    }
    ctx.globalCompositeOperation = 'source-over';
  });
}

document.addEventListener("DOMContentLoaded", RenderGraphs);

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