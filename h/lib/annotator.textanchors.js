// Generated by CoffeeScript 1.6.3
/*
** Annotator 1.2.6-dev-28a405b
** https://github.com/okfn/annotator/
**
** Copyright 2012 Aron Carroll, Rufus Pollock, and Nick Stenning.
** Dual licensed under the MIT and GPLv3 licenses.
** https://github.com/okfn/annotator/blob/master/LICENSE
**
** Built at: 2013-12-11 15:09:42Z
*/



/*
//
*/

// Generated by CoffeeScript 1.6.3
(function() {
  var TextPositionAnchor, TextRangeAnchor, _ref,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  TextPositionAnchor = (function(_super) {
    __extends(TextPositionAnchor, _super);

    TextPositionAnchor.Annotator = Annotator;

    function TextPositionAnchor(annotator, annotation, target, start, end, startPage, endPage, quote, diffHTML, diffCaseOnly) {
      this.start = start;
      this.end = end;
      TextPositionAnchor.__super__.constructor.call(this, annotator, annotation, target, startPage, endPage, quote, diffHTML, diffCaseOnly);
      if (this.start == null) {
        throw new Error("start is required!");
      }
      if (this.end == null) {
        throw new Error("end is required!");
      }
      this.Annotator = TextPositionAnchor.Annotator;
    }

    TextPositionAnchor.prototype._createHighlight = function(page) {
      var browserRange, mappings, normedRange, realRange;
      mappings = this.annotator.domMapper.getMappingsForCharRange(this.start, this.end, [page]);
      realRange = mappings.sections[page].realRange;
      browserRange = new this.Annotator.Range.BrowserRange(realRange);
      normedRange = browserRange.normalize(this.annotator.wrapper[0]);
      return new this.Annotator.TextHighlight(this, page, normedRange);
    };

    return TextPositionAnchor;

  })(Annotator.Anchor);

  TextRangeAnchor = (function(_super) {
    __extends(TextRangeAnchor, _super);

    TextRangeAnchor.Annotator = Annotator;

    function TextRangeAnchor(annotator, annotation, target, range, quote) {
      this.range = range;
      TextRangeAnchor.__super__.constructor.call(this, annotator, annotation, target, 0, 0, quote);
      if (this.range == null) {
        throw new Error("range is required!");
      }
      this.Annotator = TextRangeAnchor.Annotator;
    }

    TextRangeAnchor.prototype._createHighlight = function() {
      return new this.Annotator.TextHighlight(this, 0, this.range);
    };

    return TextRangeAnchor;

  })(Annotator.Anchor);

  Annotator.Plugin.TextAnchors = (function(_super) {
    __extends(TextAnchors, _super);

    function TextAnchors() {
      this.createFromPositionSelector = __bind(this.createFromPositionSelector, this);
      this.createFromRangeSelector = __bind(this.createFromRangeSelector, this);
      this.checkForEndSelection = __bind(this.checkForEndSelection, this);
      _ref = TextAnchors.__super__.constructor.apply(this, arguments);
      return _ref;
    }

    TextAnchors.prototype.checkDTM = function() {
      var _ref1;
      return this.useDTM = ((_ref1 = this.annotator.domMapper) != null ? _ref1.getCorpus : void 0) != null;
    };

    TextAnchors.prototype.pluginInit = function() {
      var _this = this;
      if (!this.annotator.plugins.TextHighlights) {
        throw new Error("The TextAnchors Annotator plugin requires the TextHighlights plugin.");
      }
      this.Annotator = Annotator;
      this.$ = Annotator.$;
      this.annotator.anchoringStrategies.push({
        name: "range",
        code: this.createFromRangeSelector
      });
      this.annotator.anchoringStrategies.push({
        name: "position",
        code: this.createFromPositionSelector
      });
      $(this.annotator.wrapper).bind({
        "mouseup": this.checkForEndSelection
      });
      this.Annotator.TextPositionAnchor = TextPositionAnchor;
      this.Annotator.TextRangeAnchor = TextRangeAnchor;
      this.annotator.subscribe("enableAnnotating", function(value) {
        if (value) {
          return setTimeout(_this.checkForEndSelection, 500);
        }
      });
      return null;
    };

    TextAnchors.prototype._getSelectedRanges = function() {
      var browserRange, i, normedRange, r, ranges, rangesToIgnore, selection, _i, _len;
      selection = this.Annotator.util.getGlobal().getSelection();
      ranges = [];
      rangesToIgnore = [];
      if (!selection.isCollapsed) {
        ranges = (function() {
          var _i, _ref1, _results;
          _results = [];
          for (i = _i = 0, _ref1 = selection.rangeCount; 0 <= _ref1 ? _i < _ref1 : _i > _ref1; i = 0 <= _ref1 ? ++_i : --_i) {
            r = selection.getRangeAt(i);
            browserRange = new this.Annotator.Range.BrowserRange(r);
            normedRange = browserRange.normalize().limit(this.annotator.wrapper[0]);
            if (normedRange === null) {
              rangesToIgnore.push(r);
            }
            _results.push(normedRange);
          }
          return _results;
        }).call(this);
        selection.removeAllRanges();
      }
      for (_i = 0, _len = rangesToIgnore.length; _i < _len; _i++) {
        r = rangesToIgnore[_i];
        selection.addRange(r);
      }
      return this.$.grep(ranges, function(range) {
        if (range) {
          selection.addRange(range.toRange());
        }
        return range;
      });
    };

    TextAnchors.prototype.checkForEndSelection = function(event) {
      var container, pos, r, range, selectedRanges, _i, _len;
      if (event == null) {
        event = {};
      }
      this.annotator.mouseIsDown = false;
      if (this.annotator.inAdderClick) {
        return;
      }
      selectedRanges = this._getSelectedRanges();
      for (_i = 0, _len = selectedRanges.length; _i < _len; _i++) {
        range = selectedRanges[_i];
        container = range.commonAncestor;
        if (this.Annotator.TextHighlight.isInstance(container)) {
          container = this.Annotator.TextHighlight.getIndependentParent(container);
        }
        if (this.annotator.isAnnotator(container)) {
          return;
        }
      }
      if (selectedRanges.length) {
        event.targets = (function() {
          var _j, _len1, _results;
          _results = [];
          for (_j = 0, _len1 = selectedRanges.length; _j < _len1; _j++) {
            r = selectedRanges[_j];
            _results.push(this.getTargetFromRange(r));
          }
          return _results;
        }).call(this);
        if (!event.pageX) {
          pos = selectedRanges[0].getEndCoords();
          event.pageX = pos.x;
          event.pageY = pos.y;
        }
        return this.annotator.onSuccessfulSelection(event);
      } else {
        return this.annotator.onFailedSelection(event);
      }
    };

    TextAnchors.prototype._getRangeSelector = function(range) {
      var sr;
      sr = range.serialize(this.annotator.wrapper[0]);
      return {
        type: "RangeSelector",
        startContainer: sr.startContainer,
        startOffset: sr.startOffset,
        endContainer: sr.endContainer,
        endOffset: sr.endOffset
      };
    };

    TextAnchors.prototype._getTextQuoteSelector = function(range) {
      var endOffset, prefix, quote, rangeEnd, rangeStart, startOffset, suffix, _ref1;
      if (range == null) {
        throw new Error("Called getTextQuoteSelector(range) with null range!");
      }
      rangeStart = range.start;
      if (rangeStart == null) {
        throw new Error("Called getTextQuoteSelector(range) on a range with no valid start.");
      }
      rangeEnd = range.end;
      if (rangeEnd == null) {
        throw new Error("Called getTextQuoteSelector(range) on a range with no valid end.");
      }
      if (this.useDTM) {
        startOffset = (this.annotator.domMapper.getInfoForNode(rangeStart)).start;
        endOffset = (this.annotator.domMapper.getInfoForNode(rangeEnd)).end;
        quote = this.annotator.domMapper.getCorpus().slice(startOffset, +(endOffset - 1) + 1 || 9e9).trim();
        _ref1 = this.annotator.domMapper.getContextForCharRange(startOffset, endOffset), prefix = _ref1[0], suffix = _ref1[1];
        return {
          type: "TextQuoteSelector",
          exact: quote,
          prefix: prefix,
          suffix: suffix
        };
      } else {
        return {
          type: "TextQuoteSelector",
          exact: range.text().trim()
        };
      }
    };

    TextAnchors.prototype._getTextPositionSelector = function(range) {
      var endOffset, startOffset;
      startOffset = (this.annotator.domMapper.getInfoForNode(range.start)).start;
      endOffset = (this.annotator.domMapper.getInfoForNode(range.end)).end;
      return {
        type: "TextPositionSelector",
        start: startOffset,
        end: endOffset
      };
    };

    TextAnchors.prototype.getTargetFromRange = function(range) {
      var result;
      this.checkDTM();
      result = {
        source: this.annotator.getHref(),
        selector: [this._getRangeSelector(range), this._getTextQuoteSelector(range)]
      };
      if (this.useDTM) {
        result.selector.push(this._getTextPositionSelector(range));
      }
      return result;
    };

    TextAnchors.prototype.getQuoteForTarget = function(target) {
      var selector;
      selector = this.annotator.findSelector(target.selector, "TextQuoteSelector");
      if (selector != null) {
        return this.annotator.normalizeString(selector.exact);
      } else {
        return null;
      }
    };

    TextAnchors.prototype.createFromRangeSelector = function(annotation, target) {
      var currentQuote, dfd, endInfo, endOffset, error, normedRange, range, savedQuote, selector, startInfo, startOffset, _ref1, _ref2;
      dfd = this.$.Deferred();
      selector = this.annotator.findSelector(target.selector, "RangeSelector");
      if (selector == null) {
        dfd.reject("no RangeSelector found");
        return dfd.promise();
      }
      this.checkDTM();
      try {
        range = this.Annotator.Range.sniff(selector);
        normedRange = range.normalize(this.annotator.wrapper[0]);
      } catch (_error) {
        error = _error;
        dfd.reject("failed to normalize range");
        return dfd.promise();
      }
      currentQuote = this.annotator.normalizeString((function() {
        if (this.useDTM) {
          startInfo = this.annotator.domMapper.getInfoForNode(normedRange.start);
          startOffset = startInfo.start;
          if (!startOffset) {
            throw new Error("node @ '" + startInfo.path + "' has no start field!");
          }
          endInfo = this.annotator.domMapper.getInfoForNode(normedRange.end);
          endOffset = endInfo.end;
          if (!endOffset) {
            throw new Error("node @ '" + endInfo.path + "' has no end field!");
          }
          return this.annotator.domMapper.getCorpus().slice(startOffset, +(endOffset - 1) + 1 || 9e9).trim();
        } else {
          return normedRange.text().trim();
        }
      }).call(this));
      savedQuote = this.getQuoteForTarget(target);
      if ((savedQuote != null) && currentQuote !== savedQuote) {
        dfd.reject("the saved quote doesn't match");
        return dfd.promise();
      }
      if (this.useDTM) {
        dfd.resolve(new TextPositionAnchor(this.annotator, annotation, target, startInfo.start, endInfo.end, (_ref1 = startInfo.pageIndex) != null ? _ref1 : 0, (_ref2 = endInfo.pageIndex) != null ? _ref2 : 0, currentQuote));
      } else {
        dfd.resolve(new TextRangeAnchor(this.annotator, annotation, target, normedRange, currentQuote));
      }
      return dfd.promise();
    };

    TextAnchors.prototype.createFromPositionSelector = function(annotation, target) {
      var content, currentQuote, dfd, savedQuote, selector;
      dfd = this.$.Deferred();
      this.checkDTM();
      if (!this.useDTM) {
        dfd.reject("DTM is not present");
        return dfd.promise();
      }
      selector = this.annotator.findSelector(target.selector, "TextPositionSelector");
      if (!selector) {
        dfd.reject("no TextPositionSelector found");
        return dfd.promise();
      }
      content = this.annotator.domMapper.getCorpus().slice(selector.start, +(selector.end - 1) + 1 || 9e9).trim();
      currentQuote = this.annotator.normalizeString(content);
      savedQuote = this.getQuoteForTarget(target);
      if ((savedQuote != null) && currentQuote !== savedQuote) {
        dfd.reject("the saved quote doesn't match");
        return dfd.promise();
      }
      dfd.resolve(new TextPositionAnchor(this.annotator, annotation, target, selector.start, selector.end, this.annotator.domMapper.getPageIndexForPos(selector.start), this.annotator.domMapper.getPageIndexForPos(selector.end), currentQuote));
      return dfd.promise();
    };

    return TextAnchors;

  })(Annotator.Plugin);

}).call(this);

//
//@ sourceMappingURL=annotator.textanchors.map