<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="shortcut icon" href="data:image/vnd.microsoft.icon;base64,AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAgAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAA25g0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAERAAAAAAAAAREAAAAAAAABEQAAAAAAAAERAAAAAAAAARERERAAAAABEREREAAAAAEREREQAAAAAREAAAAAAAABEQAAAAAAAAEREREQAAAAARERERAAAAABEREREAAAAAAAAAAAAAAAAAAAAAAAD//wAA//8AAPH/AADx/wAA8f8AAPH/AADwDwAA8A8AAPAPAADx/wAA8f8AAPAPAADwDwAA8A8AAP//AAD//wAA" />
    <title></title>
    <script src="https://unpkg.com/lore-engine@1.1.10/dist/lore.min.js"></script>
    <link 
      rel="stylesheet" 
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.10.2/css/all.css" 
      integrity="sha256-piqEf7Ap7CMps8krDQsSOTZgF+MU/0MPyPW2enj5I40=" 
      crossorigin="anonymous" />
    <link
      href="https://fonts.googleapis.com/css?family=Open+Sans:400,600"
      rel="stylesheet"
    />
    <style>
      body {
        margin: 0px;
        padding: 0px;
        height: 100%;
        user-select: none;
        overflow: hidden;
        white-space: nowrap;
      }

      #lore {
        position: absolute;
        width: 100%;
        height: 100%;
      }

      #title {
        position: absolute;
        z-index: 9999;
        pointer-events: none;
        text-height: 1;
        opacity: 0.0;
        transition: opacity 0.5s ease-in;
        
          padding-bottom: 20px;
        
          font-size: 1.0em;
        
          color: #888888;
        
          font-family: 'Open Sans';
        
      }

      #x-axis {
        position: absolute;
        z-index: 9999;
        pointer-events: none;
        text-height: 1;
        opacity: 0.0;
        transition: opacity 0.5s ease-in;
        
          padding-top: 20px;
        
          font-size: 0.7em;
        
          color: #888888;
        
          font-family: 'Open Sans';
        
      }

      #y-axis {
        position: absolute;
        z-index: 9999;
        pointer-events: none;
        text-height: 1;
        transition: opacity 0.5s ease-in;
        
          padding-bottom: 20px;
        
          font-size: 0.7em;
        
          color: #888888;
        
          font-family: 'Open Sans';
        
          transform: rotate(-90deg);
        
      }

      #tip {
        position: absolute;
        z-index: 9999;
        padding: 5px;
        font-family: 'Open Sans';
        background-color: rgba(255, 255, 255, 1.0);
        border-radius: 2px;
        border-left: 5px solid #000;
        pointer-events: none;
        opacity: 0.0;
        transition: opacity 0.1s ease-out;
        filter: drop-shadow(0px 0px 10px rgba(0, 0, 0, 1.0));
      }

      #tip.show {
        opacity: 1.0;
        transition: opacity 0.1s ease-out;
      }

      #tip-text {
        position: relative;
        max-width: 500px;
        white-space: normal;
        line-break: normal;
      }

      #hover-indicator {
        display: none;
        position: absolute;
        z-index: 999;
        border: 1px solid #fff;
        background-color: rgba(255, 255, 255, 0.25);
        border-radius: 50%;
        pointer-events: none;
      }

      #hover-indicator.show {
        display: block !important
      }

      .selected-indicator {
        position: absolute;
        z-index: 999;
        pointer-events: none;
      }

      .selected-indicator .crosshair-x {
        position: absolute;
        top: 0; left: 0; bottom: 0; right: 0;
        height: 2px;
        width: 100%;
        margin: auto;
        
          background-color: #fff;
        
      }

      .selected-indicator .crosshair-y {
        position: absolute;
        top: 0; left: 0; bottom: 0; right: 0;
        width: 2px;
        height: 100%;
        margin: auto;
        
          background-color: #fff;
        
      }

      #legend {
        position: absolute;
        z-index: 9998;
        
          bottom: 10px;
        
          right: 10px;
        
          padding: 10px;
        
          border: 1px solid #262626;
        
          border-radius: 2px;
        
          background-color: #111111;
        
          filter: drop-shadow(0px 0px 10px rgba(0, 0, 0, 0.5));
        
          color: #eeeeee;
        
          font-family: 'Open Sans';
        
      }

      #legend .container {
        display: flex;
        flex: auto;
        align-items: flex-start;
        
        flex-direction: column;
        
      }

      #legend .legend-section {
        width: 100%;
      }

      #legend .legend-section:not(:first-child) {
        
      }

      #legend h2 {
        font-size: 1em;
        font-weight: 600;
        padding-top: 0;
        margin-top: 0;
        margin-bottom: 5px;
        text-align: center;
        max-width: 250px;
        white-space: normal;
      }

      #legend h3 {
        font-size: 0.8em;
        margin-top: 10px;
        margin-bottom: 0px;
        max-width: 250px;
        white-space: normal;
      }

      #legend select {
        width: 100%;
        margin-bottom: 5px;
        background: transparent;
        color: #fff;
        border-radius: 2px;
        font-size: 0.75em;
      }

      #legend select option {
        background: #000;
      }

      #legend .legend-element, #legend .legend-element-range {
        position: relative;
        display: flex;
        flex: auto;
        align-items: flex-start;
        padding-bottom: 2px;
        padding-top: 2px;
      }

      #legend .legend-element {
        align-items: flex-start;
      }

      #legend .legend-element-range {
        flex-direction: column;
      }

      #legend .color-box {
        
          width: 15px;
        
          height: 15px;
        
          border: solid 0px;
        
      }

      #legend .color-stripe {
        
          width: 15px;
        
          height: 1px;
        
          border: solid 0px;
        
      }

      #legend .legend-label {
        height: 15px;
        font-size: 0.7em;
        padding-left: 5px;
      }

      #legend .legend-label.max {
        position: absolute;
        top: 0px;
        margin-left: 15px;
      }

      #legend .legend-label.min {
        position: absolute;
        bottom: 2px;
        margin-left: 15px;
      }

      #selected {
        position: absolute;
        display: none;
        z-index: 9998;
        width: 250px;
        
          bottom: 10px;
        
          left: 10px;
        
          padding: 0px;
        
          border: 1px solid #262626;
        
          border-radius: 2px;
        
          background-color: #111111;
        
          filter: drop-shadow(0px 0px 10px rgba(0, 0, 0, 0.5));
        
          color: #eeeeee;
        
          font-family: 'Open Sans';
        
      }

      #selected #selected-controls {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        padding: 5px 10px;
        border-bottom: 1px solid #262626;
        font-size: 0.8em;
        font-weight: bold;
      }

      #selected #selected-controls * {
        display: inline-block;
      }

      #selected #selected-controls #selected-title {
        flex-grow: 1;
        white-space: nowrap; 
        overflow: hidden;
        text-overflow: ellipsis;
        color: #aaa;
      }

      #selected #selected-controls a {
        margin: 0px 2px;
        font-size: 1.5em;
        color: #fff;
        opacity: 0.75;
        transition: 0.2s;
      }

      #selected #selected-controls a:hover {
        opacity: 1.0;
      }

      #selected #selected-controls a#selected-remove {
        position: absolute;
        right: 10px;
        top: 42px;
        color: #e74c3c;
      }

      #selected #selected-container {
        padding: 10px;
        font-size: 0.8em;
      }

      #selected #selected-container .label {
        font-weight: bold;
        color: #aaa;
        font-size: 0.7em;
      }

      #selected #selected-container .label:not(:first-child) {
        margin-top: 2px;
      }

      #selected #selected-container .content {
        white-space: nowrap; 
        overflow: hidden;
        text-overflow: ellipsis;
      }

      #selected #selected-container .content a {
        text-decoration: none;
        color: #3498db;
      }

      #controls {
        position: absolute;
        z-index: 9998;
        
          top: 10px;
        
          right: 10px;
        
          padding: 2px;
        
          border: 1px solid #262626;
        
          border-radius: 2px;
        
          background-color: #111111;
        
          filter: drop-shadow(0px 0px 10px rgba(0, 0, 0, 0.5));
        
          color: #eeeeee;
        
          font-family: 'Open Sans';
        
      }

      #controls a {
        display: inline-block;
        padding: 5px 10px;
        font-size: 1.2em;
        color: #fff;
        opacity: 0.75;
        transition: 0.2s;
      }

      #controls a:hover {
        opacity: 1.0;
      }

      #controls #more-controls {
        display: inline-block;
      }

      #impress {
        position: absolute;
        z-index: 9999;
        top: 10px;
        left: 10px;
        font-size: 0.7em;
        color: #eee;
      }

      #impress a {
        color: #3498db;
        text-decoration: none;
      }

      .show {
        opacity: 1.0 !important;
      }

      .hide {
        display: none !important;
      }

      @media only screen and (max-width: 600px) {
        #selected {
          position: absolute;
          display: none;
          z-index: 9998;
          width: 125px;
          opacity: 0.8;
          background-filter: blur(10px);
        }

        #tip {
          display: none;
        }
      }
    </style>
  </head>

  <body>
    
    
    
    

    <div id="tip" data-bind="tip">
      <div id="tip-text" data-bind="tipText"></div>
    </div>
    <div id="selected" data-bind="selected">
      <div id="selected-controls" data-bind="selectedControls">
        <a id="selected-toggle" data-bind="selectedToggle" href="#">
          <i class="fas fa-toggle-on"></i>
        </a>
        <span>&nbsp;&nbsp;</span>
        <span id="selected-title" data-bind="selectedTitle"></span>
        <span>&nbsp;&nbsp;</span>
        <span id="selected-current" data-bind="selectedCurrent" data-bind="selectedCurrent">0</span><span> / </span><span id="selected-total" data-bind="selectedTotal">0</span>
        <span>&nbsp;&nbsp;</span>
        <a id="selected-prev" data-bind="selectedPrev" href="#">
          <i class="fas fa-angle-left"></i>
        </a>
        <span>&nbsp;</span>
        <a id="selected-next" data-bind="selectedNext" href="#">
          <i class="fas fa-angle-right"></i>
        </a>
        <a id="selected-remove" data-bind="selectedRemove" href="#">
          <i class="fas fa-times"></i>
        </a>
      </div>
      <div id="selected-container" data-bind="selectedContainer">
      </div>
    </div>
    <div id="controls" data-bind="controls">
      <div id="more-controls" data-bind="moreControls" class="hide">
        <a id="search" data-bind="search" href="#">
          <i class="fas fa-search"></i>
        </a>
        <a id="export" data-bind="export" href="#">
          <i class="fas fa-camera"></i>
        </a>
      </div>
      <a id="show-controls" data-bind="showControls" href="#">
        <i class="fas fa-bars"></i>
      </a>
    </div>
    <div id="hover-indicator" data-bind="hoverIndicator"></div>
    <canvas id="lore"></canvas>

    
    <script src="server_data.js"></script>
    
    <script>
      class Faerun {
        constructor() {
          this.body = document.getElementsByTagName('body')[0];

          this.selectedItems = [];
          this.selectedIndicators = [];
          this.selectedCurrent = [];
          this.scatterMeta = [{"categorical": [false], "fog_intensity": 0.0, "has_legend": false, "interactive": true, "is_range": [false], "label_index": [0], "legend": [[]], "legend_title": ["server_data"], "mapping": {"c": "c", "cs": "cs", "knn": "knn", "labels": "labels", "s": "s", "x": "x", "y": "y", "z": "z"}, "max_c": [1.0], "max_legend_label": ["1.00"], "max_point_size": 10, "min_c": [0.0], "min_legend_label": ["0.00"], "name": "server_data", "ondblclick": [null], "point_scale": 1, "selected_labels": [null], "series_title": [null], "shader": "smoothCircle", "title_index": [0]}];
          this.treeMeta = [{"color": "#666666", "fog_intensity": 0.0, "mapping": {"c": "c", "from": "from", "to": "to", "x": "x", "y": "y", "z": "z"}, "name": "server_data_tree", "point_helper": "server_data"}];
          this.seriesState = {};
          this.el = {};

          this.currentPoint = null;

          this.lore = null;
          this.clearColorHex = '#ffffff';
          this.clearColor = null;
          this.view = 'front';
          this.antiAliasing = true;
          this.alphaBlending = false;

          this.treeHelpers = [];
          this.pointHelpers = [];
          this.octreeHelpers = [];
          this.coordinatesHelper = null;

          this.min = [Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE];
          this.max = [-Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE];
          this.maxRadius = -Number.MAX_VALUE;

          this.octreeHelpers = [];
          this.ohIndexToPhName = [];
          this.ohIndexToPhIndex = [];
          this.phIndexMap = {};
          this.ohIndexMap = {};

          this.coords = {
            show: false,
            grid: false,
            ticks: true,
            tickCount: 10,
            tickLength: 2.0,
            color: '#888888',
            box: false,
            offset: 5.0
          };

          this.legend = {
            show: false,
            title: 'Legend'
          };

          this.el = Faerun.bindElements();

          this.scatterMeta.forEach(s => {
            this.seriesState[s.name] = 0;
          });

          this.clearColor = Lore.Core.Color.fromHex(this.clearColorHex);
          this.alphaBlending = (this.view === 'free' ? false : true) || this.alphaBlending;

          this.initLore();
          this.initTreeHelpers();
          this.initPointHelpers();
          this.initCoords();
          this.initAxes();
          this.initView();
          this.initEvents();
          this.renderLegend();
        }

        initLore() {
          this.lore = Lore.init('lore', {
            antialiasing: this.antiAliasing,
            clearColor: this.clearColorHex,
            alphaBlending: this.alphaBlending,
            preserveDrawingBuffer: true
          });
        }

        initTreeHelpers() {
          this.treeMeta.forEach(t => {
            let th = new Lore.Helpers.TreeHelper(this.lore, t.name, 'tree');
            th.setXYZHexS(data[t.name].x, data[t.name].y, data[t.name].z, t.color);
            th.setFog([this.clearColor.components[0], this.clearColor.components[1], 
                       this.clearColor.components[2], this.clearColor.components[3]],
                      t.fog_intensity);
            this.treeHelpers.push(th);
          });
        }

        initPointHelpers() {
          this.scatterMeta.forEach(s => {           
            let ph = new Lore.Helpers.PointHelper(
              this.lore, s.name, s.shader, { maxPointSize: s.max_point_size }
            );

            ph.setXYZRGBS(data[s.name].x, data[s.name].y, data[s.name].z, 
                          data[s.name]['colors'][0].r, data[s.name]['colors'][0].g, 
                          data[s.name]['colors'][0].b, data[s.name]['s'] ? data[s.name]['s'][0] : 1.0);

            ph.setPointScale(s.point_scale);
            ph.setFog([this.clearColor.components[0], this.clearColor.components[1],
                       this.clearColor.components[2], this.clearColor.components[3]],
                      s.fog_intensity)

            this.phIndexMap[s.name] = this.pointHelpers.length;
            this.pointHelpers.push(ph);

            this.min[0] = Faerun.getMin(data[s.name].x, this.min[0]);
            this.min[1] = Faerun.getMin(data[s.name].y, this.min[1]);
            this.min[2] = Faerun.getMin(data[s.name].z, this.min[2]);
            this.max[0] = Faerun.getMax(data[s.name].x, this.max[0]);
            this.max[1] = Faerun.getMax(data[s.name].y, this.max[1]);
            this.max[2] = Faerun.getMax(data[s.name].z, this.max[2]);
            this.maxRadius = ph.getMaxRadius();
    
            if (s.interactive && data[s.name].labels) {
              this.octreeHelpers.push(
                new Lore.Helpers.OctreeHelper(this.lore, 'Octree_' + s.name, 'tree', ph)
              );

              this.ohIndexMap[s.name] = this.octreeHelpers.length - 1;
              this.ohIndexToPhName.push(s.name);
              this.ohIndexToPhIndex.push(this.phIndexMap[s.name]);
            }
          });
        }

        initCoords() {
          if (!this.coords.show) return;

          let min = [0, 0, 0];
          let max = [0, 0, 0];

          for (var i = 0; i < 3; i++) {
            min[i] = this.min[i] - this.coords.offset;
            max[i] = this.max[i] + this.coords.offset;
          }

          this.coordinatesHelper = new Lore.Helpers.CoordinatesHelper(this.lore, 'Coordinates', 'coordinates', {
            position: new Lore.Math.Vector3f(min[0], min[1], min[2]),
            axis: {
              x: {
                length: max[0] - min[0],
                color: Lore.Core.Color.fromHex(this.coords.color)
              },
              y: {
                length: max[1] - min[1],
                color: Lore.Core.Color.fromHex(this.coords.color)
              },
              z: {
                length: max[2] - min[2],
                color: Lore.Core.Color.fromHex(this.coords.color)
              }
            },
            ticks: {
              enabled: this.coords.ticks,
              x: {
                length: this.coords.tickLength,
                color: Lore.Core.Color.fromHex(this.coords.color),
                count: this.coords.tickCount
              },
              y: {
                length: this.coords.tickLength,
                color: Lore.Core.Color.fromHex(this.coords.color),
                count: this.coords.tickCount
              },
              z: {
                length: this.coords.tickLength,
                color: Lore.Core.Color.fromHex(this.coords.color),
                count: this.coords.tickCount
              }
            },
            box: {
              enabled: this.coords.box,
              x: {
                color: Lore.Core.Color.fromHex(this.coords.color)
              },
              y: {
                color: Lore.Core.Color.fromHex(this.coords.color)
              },
              z: {
                color: Lore.Core.Color.fromHex(this.coords.color)
              }
            }
          });
        }

        initAxes() {
          // Wait for DOM to get ready
          setTimeout(() => {
            this.updateTitle(true);
            this.updateXAxis(true);
            this.updateYAxis(true);
          }, 500);
        }

        initView() {
          let center = new Lore.Math.Vector3f(
              (this.max[0] + this.min[0]) / 2.0, 
              (this.max[1] + this.min[1]) / 2.0, 
              (this.max[2] + this.min[2]) / 2.0
            );
          this.lore.controls.setLookAt(center);
          this.lore.controls.setRadius(this.maxRadius + 100);
          this.lore.controls.setView(0.9, -0.5)
          this.lore.controls.setViewByName(this.view);
        }

        initEvents() {
          this.lore.controls.addEventListener('updated', () => {
            // Update the position / content of the annotations every time
            // the view changes
            this.updateTitle();
            this.updateYAxis();
            this.updateXAxis();
            this.updateSelectedIndicators();
          });

          Lore.Helpers.OctreeHelper.joinHoveredChanged(this.octreeHelpers, e => {
            let phName = this.ohIndexToPhName[e.source];
            if (e.e && data[phName].labels) {
              let fullLabel = data[phName].labels[e.e.index];
              let labelIndex = this.scatterMeta[this.ohIndexToPhIndex[e.source]]
                                  .label_index[this.seriesState[phName]];

              let rgbColor = this.pointHelpers[e.source].getColor(e.e.index);
              let hexColor = Lore.Core.Color.rgbToHex(rgbColor[0], rgbColor[1], rgbColor[2]);

              this.currentPoint = {
                index: e.e.index,
                fullLabel: fullLabel,
                source: phName,
                label: fullLabel.split('__')[labelIndex],
                color: hexColor
              }
              
              this.setTipContent();
              this.el.tip.classList.add('show');

              let pointSize = this.pointHelpers[e.source].getPointSize() / window.devicePixelRatio;
              let x = e.e.screenPosition[0];
              let y = e.e.screenPosition[1];

              this.el.hoverIndicator.style.width = pointSize + 'px';
              this.el.hoverIndicator.style.height = pointSize + 'px';
              this.el.hoverIndicator.style.left = (x - pointSize / 2.0 - 1) + 'px';
              this.el.hoverIndicator.style.top = (y - pointSize / 2.0 - 1) + 'px';

              this.el.hoverIndicator.classList.add('show');
            } else {
              this.currentPoint = null;
              this.el.tip.classList.remove('show');
              this.el.hoverIndicator.classList.remove('show');
            }
          });

          Lore.Helpers.OctreeHelper.joinSelectedChanged(this.octreeHelpers, items => {
            this.selectedItems = items;
            this.updateSelected();
          });

          Lore.Helpers.OctreeHelper.joinReselected(this.octreeHelpers, item => {
            this.updateSelected(
              this.getSelectedIndex(item[0].source, item[0].item.e.index)
            );
          });

          // Event listeners
          this.el.selectedPrev.addEventListener('click', e => {
            e.preventDefault();
            this.updateSelected(this.selectedCurrent - 1);
            return false;
          });

          this.el.selectedNext.addEventListener('click', e => {
            e.preventDefault();
            this.updateSelected(this.selectedCurrent + 1);
            return false;
          });

          this.el.selectedRemove.addEventListener('click', e => {
            e.preventDefault();
            let item = this.selectedItems[this.selectedCurrent]
            this.octreeHelpers[item.source].removeSelected(item.index);
            return false;
          });

          document.addEventListener('dblclick', e => {
            if (this.currentPoint) {
              var index = this.currentPoint.index;
              var labels = this.currentPoint.label.split('__');
              var source = this.currentPoint.source;
              eval(this.scatterMeta[this.phIndexMap[source]].ondblclick[this.seriesState[source]]);
            }
          });

          document.addEventListener('mousemove', e => {
            let x = e.clientX;
            let y = e.clientY;

            if (x > window.innerWidth - this.el.tip.offsetWidth - 20) {
              x -= this.el.tip.offsetWidth;
            } else {
              x += 10;
            }

            if (y > window.innerHeight - this.el.tip.offsetHeight - 20) {
              y -= this.el.tip.offsetHeight;
            } else {
              y += 10;
            }

            if (this.el.tip) {
              this.el.tip.style.top = y + 'px';
              this.el.tip.style.left = x + 'px';
            }
          });

          this.el.selectedToggle.addEventListener('click', e => {
            this.el.selectedContainer.classList.toggle('hide');
            if (this.el.selectedContainer.classList.contains('hide'))
              this.el.selectedToggle.innerHTML = '<i class="fas fa-toggle-off"></i>';
            else
              this.el.selectedToggle.innerHTML = '<i class="fas fa-toggle-on"></i>';
          });
          
          this.el.showControls.addEventListener('click', e => {
            this.el.moreControls.classList.toggle('hide');
            e.preventDefault();
            return false;
          });

          this.el.search.addEventListener('click', e => {
            this.search();
            e.preventDefault();
            return false;
          });

          window.addEventListener('keydown', e => {
            if ((e.keyCode == 114) || (e.ctrlKey && e.keyCode == 70)) {
              this.search();
              e.preventDefault();
              return false;
            }
          });

          this.el.export.addEventListener('click', e => {
            e.preventDefault();

            let canvas = document.getElementById('lore');
            let zoom = this.lore.controls.getZoom();

            canvas.style.width = (canvas.width * 2) + 'px';
            canvas.style.height = (canvas.height * 2) + 'px';
            this.lore.controls.setZoom(zoom * 2);

            setTimeout(() => {
              let blob = this.lore.canvas.toBlob(blob => {
                let a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.setAttribute('download', 'export.png');
                a.click();
                
                setTimeout(() => {
                  canvas.style.width = '100%';
                  canvas.style.height = '100%';
                  this.lore.controls.setZoom(zoom);
                }, 2000);
              });
            }, 2000);
          });
        }

        setTipContent() {
          this.el.tipText.innerHTML = this.currentPoint.label;
          this.el.tip.style.borderColor = this.currentPoint.color;
        }

        setSelectedContent(fullLabel, labelIndex, selectedLabels) {
          this.el.selectedContainer.innerHTML = '';
          fullLabel.forEach((l, i) => {
            if (i === labelIndex) return;
            if (selectedLabels && selectedLabels[i]) {
              this.el.selectedContainer.appendChild(
                Faerun.createElement('div', { classes: 'label', content: selectedLabels[i] })
              );
            }
            this.el.selectedContainer.appendChild(
              Faerun.createElement('div', { classes: 'content', content: l })
            );
          });

          // Update the indicator
          this.updateSelectedIndicators();
        }

        renderLegend() {
          if (!this.legend.show) return;

          let legend = document.getElementById('legend');
          
          if (legend) this.body.removeChild(legend);

          legend = Faerun.createElement('div', { id: 'legend' });
          this.body.appendChild(legend)
          
          if (this.legend.title && this.legend.title !== '')
            legend.appendChild(Faerun.createElement('h2', { content: 'Legend' }));
          
          let container = Faerun.createElement('div', { classes: 'container' });
          legend.appendChild(container);

          this.scatterMeta.forEach(s => {
            let index = this.seriesState[s.name];
            if (s.has_legend) {
              let legendSection = []
              if (!s.is_range[index]) {
                s.legend[index].forEach(v => {
                  legendSection.push(Faerun.createElement('div', { classes: 'legend-element' }, [
                    Faerun.createColorBox(v[0]),
                    Faerun.createElement('div', { classes: 'legend-label', content: v[1] }),
                  ]))
                })
              } else {
                legendSection.push(Faerun.createElement('div', { classes: 'legend-element-range' }, [
                  ...Faerun.createColorScale(s.legend[index]),
                  Faerun.createElement('div', { 
                    classes: 'legend-label max', 
                    content: s.max_legend_label[index] 
                  }),
                  Faerun.createElement('div', {
                    classes: 'legend-label min',
                    content: s.min_legend_label[index] 
                  })
                ]))
              }

              let series = [];
              for (var i = 0; i < s.series_title.length; i++) {
                series.push(
                  Faerun.createElement('option', { 
                    value: i, 
                    content: s.series_title[i], 
                    selected: i === index
                  })
                );
              }


              let sectionHeader = Faerun.createElement(
                'h3', { content: s.legend_title[index] }
              );
              sectionHeader.addEventListener('click', e => {
                this.toggleLegendSection(s.name);
              });

              let seriesSelector = Faerun.createElement(
                'select', 
                { 
                  id: `select-${s.name}`, 
                  classes: 'series-selector',
                  'data-name': s.name,
                  hidden: s.series_title.length < 2,
                }, 
                [ ...series ]
              );
              seriesSelector.addEventListener('change', e => {
                let value = document.getElementById(`select-${s.name}`).value;
                this.changeSeries(value, s.name);
              });


              container.appendChild(
                Faerun.createElement(
                  'div', { id: `legend-${s.name}`, 
                  classes: 'legend-section', 
                  'data-name': `${s.name}` },
                  [ sectionHeader, seriesSelector, ...legendSection ]
                )
              );
            }
          });
        }

        toggleLegendSection(name) {
          let section = document.getElementById('legend-' + name);
          let geometry = this.pointHelpers[this.phIndexMap[name]].geometry;
          let isVisible = geometry.isVisible;

          if (isVisible) {
            geometry.hide();
            section.style.opacity = 0.5;
          } else {
            geometry.show();
            section.style.opacity = 1.0;
          }
        }

        getSelectedIndex(source, index) {
          let selectedIndex = null;
          this.selectedItems.forEach((item, i) => {
            if (item.source == source && item.item.index == index) {
              selectedIndex = i;
              return;
            }
          });
          return selectedIndex;
        }

        updateSelected(current = -1) {
          let n = this.selectedItems.length
          // Hide the container if no items are selected
          if (n === 0) {
            this.el.selected.style.display = 'none';
            return;
          } else {
            this.el.selected.style.display = 'block';
          }

          if (current < 0) current = n - 1;
          if (current >= n) current = 0;
          this.selectedCurrent = current;

          let item = this.selectedItems[current];

          let phIndex = this.ohIndexToPhIndex[item.source];
          let meta = this.scatterMeta[phIndex];
          let phName = this.ohIndexToPhName[item.source];
          let seriesState = this.seriesState[phName];

          let fullLabel = data[phName].labels[item.item.index].split('__');

          let labelIndex = meta.label_index[seriesState];
          let titleIndex = meta.title_index[seriesState];
          let selectedLabels = meta.selected_labels[seriesState];

          this.el.selectedCurrent.innerHTML = current + 1;
          this.el.selectedTotal.innerHTML = n;
          this.el.selectedTitle.innerHTML = fullLabel[titleIndex];

          this.setSelectedContent(fullLabel, labelIndex, selectedLabels);

          // Remove all indicators
          this.selectedIndicators.forEach(indicator => {
            indicator.element.parentElement.removeChild(indicator.element);
          });
          this.selectedIndicators.length = 0;

          // Add the indicator for this object
          let indicatorElement = Faerun.createElement(
            'div', 
            { classes: 'selected-indicator' },
            [
              Faerun.createElement('div', { classes: 'crosshair-x' }),
              Faerun.createElement('div', { classes: 'crosshair-y' })
            ]
          );

          this.body.appendChild(indicatorElement);
          this.selectedIndicators.push({
            element: indicatorElement,
            index: item.item.index,
            ohIndex: item.source,
            phIndex: phIndex
          });
          this.updateSelectedIndicators();
        }

        updateSelectedIndicators() {
          this.selectedIndicators.forEach(indicator => {
            let pointSize = this.pointHelpers[indicator.phIndex].getPointSize();
            let screenPosition = this.octreeHelpers[indicator.ohIndex]
                                     .getScreenPosition(indicator.index);
            
            // Make the crosshairs larger than the point
            pointSize = Faerun.getMax([pointSize / window.devicePixelRatio, 10 / window.devicePixelRatio]);
            pointSize *= 1.25;
            let halfPointSize = pointSize / 2.0;
            indicator.element.style.left = (screenPosition[0] - halfPointSize) + 'px';
            indicator.element.style.top = (screenPosition[1] - halfPointSize) + 'px';
            indicator.element.style.width = pointSize + 'px';
            indicator.element.style.height = pointSize + 'px';
          });
        }

        updateTitle(first = false) {
          if (this.el.title === undefined) return;

          let bb = this.el.title.getBoundingClientRect();
          let scenePosition = new Lore.Math.Vector3f(
            (this.min[0] + this.min[0]) / 2.0, this.min[1], 
            (this.min[2] + this.min[2]) / 2.0
          );

          let screenPosition = this.lore.controls.camera.sceneToScreen(scenePosition, this.lore);
          
          this.el.title.style.left = (screenPosition[0] - (bb.width / 2.0)) + 'px';
          this.el.title.style.top = (screenPosition[1] - bb.height) + 'px';

          if (first) this.el.title.classList.add('show');
        }

        updateXAxis(first = false) {
          if (this.el.xAxis === undefined) return;
          
          let bb = this.el.xAxis.getBoundingClientRect();
          let scenePosition = new Lore.Math.Vector3f(
            (this.min[0] + this.min[0]) / 2.0, this.min[1], 
            (this.min[2] + this.min[2]) / 2.0
          );

          let screenPosition = this.lore.controls.camera.sceneToScreen(scenePosition, this.lore);
          
          this.el.xAxis.style.left = (screenPosition[0] - (bb.width / 2.0)) + 'px';
          this.el.xAxis.style.top = (screenPosition[1]) + 'px';

          if (first) this.el.xAxis.classList.add('show');
        }

        updateYAxis(first = false) {
          if (this.el.yAxis === undefined) return;
            
          let bb = this.el.yAxis.getBoundingClientRect();
          let scenePosition = new Lore.Math.Vector3f(
            this.min[0], (this.min[1] + this.min[1]) / 2.0, 
            (this.min[2] + this.min[2]) / 2.0
          );
          
          let screenPosition = this.lore.controls.camera.sceneToScreen(scenePosition, this.lore);
          
          this.el.yAxis.style.left = (screenPosition[0] - bb.height) + 'px';
          this.el.yAxis.style.top = (screenPosition[1] - bb.width / 2.0) + 'px';

          if (first) this.el.yAxis.classList.add('show');
        }

        changeSeries(value, name) {
          value = parseInt(value);
          this.seriesState[name] = value;
          this.renderLegend();

          this.pointHelpers[this.phIndexMap[name]].setRGBFromArrays(
            data[name]['colors'][value].r, 
            data[name]['colors'][value].g, 
            data[name]['colors'][value].b
          );

          if (data[name]['s']) {
            if (data[name]['s'][value]) {
              this.pointHelpers[this.phIndexMap[name]].setSize(
                data[name]['s'][value]
              );
            } else {
              this.pointHelpers[this.phIndexMap[name]].setSize(1.0);
            }
          }
        }

        search() {
          let searchTerm = prompt('Please enter a search term:', '');
          if (!searchTerm) return;

          let results = {}
          let re = new RegExp(searchTerm, 'i');
          Object.keys(data).forEach(name => {
            if (!('labels' in data[name])) return;
            results[name] = []
            data[name]['labels'].forEach((label, i) => {
              if (re.test(label))
                results[name].push(i);
            });
          });

          for (const [name, indices] of Object.entries(results)) {
            if (!name in this.ohIndexMap) return;
            indices.forEach(index => {
              this.octreeHelpers[this.ohIndexMap[name]].addSelected(index);
            });
          }
        }

        static createColorBox(value) {
          return Faerun.createElement(
            'div', 
            { 
              classes: 'color-box', 
              style: `background-color: rgba(${value[0] * 255}, ${value[1] * 255 }, ${value[2] * 255 }, ${value[3] });
                      border-color: rgba(${value[0] * 255 }, ${value[1] * 255 }, ${value[2] * 255 }, ${value[3] })`
            }
          );
        }

        static createColorScale(values) {
          let scale = [];

          values.forEach(value => {
            scale.push(
              Faerun.createElement(
                'div', 
                { 
                  classes: 'color-stripe', 
                  style: `background-color: rgba(${value[0][0] * 255}, ${value[0][1] * 255}, ${value[0][2] * 255}, ${value[0][3]});
                          border-color: rgba(${value[0][0] * 255}, ${value[0][1] * 255}, ${value[0][2] * 255}, ${value[0][3]})`,
                  alt: value[1]
                }
              ),
            )
          });

          return scale;
        }
        
        static createElement(tag, values, children) {
          let element = document.createElement(tag);

          for (const key of Object.keys(values)) {
            if (key === 'classes')
              element.classList.add(...values[key].split(' '));
            else if (key === 'content')
              element.innerHTML = values[key];
            else if (key === 'hidden') {
              if (values[key])
                element.setAttribute('hidden', true);
            }
            else if (key === 'selected') {
              if (values[key])
                element.setAttribute('selected', true);
            }
            else
              element.setAttribute(key, values[key]);
          }

          if (children) {
            if (Array.isArray(children)) {
              children.forEach(child => {
                element.appendChild(child);
              })
            } else {
              element.appendChild(children);
            }
          }

          return element;
        }

        static bindElements() {
          let result = {};
          document.querySelectorAll('[data-bind]').forEach(e => {
            result[e.getAttribute('data-bind')] = e;
          });
          return result;
        }

        static getMin(arr, other = Number.MAX_VALUE) {
          let m = Number.MAX_VALUE;
          for (var i = 0; i < arr.length; i++)
              if (arr[i] < m) m = arr[i];
          
          if (m < other) return m;
          return other;
        }

        static getMax(arr, other = -Number.MAX_VALUE) {
          let m = -Number.MAX_VALUE;
          for (var i = 0; i < arr.length; i++)
              if (arr[i] > m) m = arr[i];
          
          if (m > other) return m;
          return other;
        }
      }

      let f = new Faerun();
    </script>
  </body>
</html>