


import math

from p2pool.util import math as math2


class DataViewDescription(object):
    def __init__(self, bin_count, total_width):
        self.bin_count = bin_count
        self.bin_width = total_width/bin_count

def _shift(x, shift, pad_item):
    left_pad = math2.clip(shift, (0, len(x)))
    right_pad = math2.clip(-shift, (0, len(x)))
    return [pad_item]*left_pad + x[right_pad:-left_pad if left_pad else None] + [pad_item]*right_pad

combine_bins = math2.add_dicts_ext(lambda left, right: (left[0]+right[0], left[1]+right[1]), (0, 0))

nothing = object()
def keep_largest(n, squash_key=nothing, key=lambda x: x, add_func=lambda a, b: a+b):
    def _(d):
        items = sorted(iter(d.items()), key=lambda k_v: (k_v[0] != squash_key, key(k_v[1])), reverse=True)
        while len(items) > n:
            k, v = items.pop()
            if squash_key is not nothing:
                items[-1] = squash_key, add_func(items[-1][1], v)
        return dict(items)
    return _

def _shift_bins_so_t_is_not_past_end(bins, last_bin_end, bin_width, t):
    # returns new_bins, new_last_bin_end
    shift = max(0, int(math.ceil((t - last_bin_end)/bin_width)))
    return _shift(bins, shift, {}), last_bin_end + shift*bin_width

class DataView(object):
    def __init__(self, desc, ds_desc, last_bin_end, bins):
        assert len(bins) == desc.bin_count
        
        self.desc = desc
        self.ds_desc = ds_desc
        self.last_bin_end = last_bin_end
        self.bins = bins
    
    def _add_datum(self, t, value):
        if not self.ds_desc.multivalues:
            value = {'null': value}
        elif self.ds_desc.multivalue_undefined_means_0 and 'null' not in value:
            value = dict(value, null=0) # use null to hold sample counter
        self.bins, self.last_bin_end = _shift_bins_so_t_is_not_past_end(self.bins, self.last_bin_end, self.desc.bin_width, t)
        
        bin = int(math.floor((self.last_bin_end - t)/self.desc.bin_width))
        assert bin >= 0
        if bin < self.desc.bin_count:
            self.bins[bin] = self.ds_desc.keep_largest_func(combine_bins(self.bins[bin], dict((k, (v, 1)) for k, v in value.items())))
    
    def get_data(self, t):
        bins, last_bin_end = _shift_bins_so_t_is_not_past_end(self.bins, self.last_bin_end, self.desc.bin_width, t)
        assert last_bin_end - self.desc.bin_width <= t <= last_bin_end
        
        def _(xxx_todo_changeme):
            (i, bin) = xxx_todo_changeme
            left, right = last_bin_end - self.desc.bin_width*(i + 1), min(t, last_bin_end - self.desc.bin_width*i)
            center, width = (left+right)/2, right-left
            if self.ds_desc.is_gauge and self.ds_desc.multivalue_undefined_means_0:
                real_count = max([0] + [count for total, count in bin.values()])
                if real_count == 0:
                    val = None
                else:
                    val = dict((k, total/real_count) for k, (total, count) in bin.items())
                default = 0
            elif self.ds_desc.is_gauge and not self.ds_desc.multivalue_undefined_means_0:
                val = dict((k, total/count) for k, (total, count) in bin.items())
                default = None
            else:
                val = dict((k, total/width) for k, (total, count) in bin.items())
                default = 0
            if not self.ds_desc.multivalues:
                val = None if val is None else val.get('null', default)
            return center, val, width, default
        return list(map(_, enumerate(bins)))


class DataStreamDescription(object):
    def __init__(self, dataview_descriptions, is_gauge=True, multivalues=False, multivalues_keep=20, multivalues_squash_key=None, multivalue_undefined_means_0=False, default_func=None):
        self.dataview_descriptions = dataview_descriptions
        self.is_gauge = is_gauge
        self.multivalues = multivalues
        self.keep_largest_func = keep_largest(multivalues_keep, multivalues_squash_key, key=lambda t_c: t_c[0]/t_c[1] if self.is_gauge else t_c[0], add_func=lambda left, right: (left[0]+right[0], left[1]+right[1]))
        self.multivalue_undefined_means_0 = multivalue_undefined_means_0
        self.default_func = default_func

class DataStream(object):
    def __init__(self, desc, dataviews):
        self.desc = desc
        self.dataviews = dataviews
    
    def add_datum(self, t, value=1):
        for dv in self.dataviews.values():
            dv._add_datum(t, value)


class HistoryDatabase(object):
    @classmethod
    def from_obj(cls, datastream_descriptions, obj=None):
        obj = {} if obj is None else obj

        def convert_bin(bin):
            if isinstance(bin, dict):
                return bin
            total, count = bin
            if not isinstance(total, dict):
                total = {'null': total}
            return dict((k, (v, count)) for k, v in total.items()) if count else {}
        def new_dataview(ds_name, ds_desc, dv_name, dv_desc):
            if ds_desc.default_func is None:
                return DataView(dv_desc, ds_desc, 0, dv_desc.bin_count*[{}])
            return ds_desc.default_func(
                ds_name, ds_desc, dv_name, dv_desc, obj)
        def resize_dataview(ds_desc, dv_desc, dv_data):
            old_bin_width = dv_data.get('bin_width')
            old_last_bin_end = dv_data.get('last_bin_end')
            old_bins = dv_data.get('bins')
            if not old_bin_width or old_last_bin_end is None or not old_bins:
                return None
            bins = dv_desc.bin_count*[{}]
            for i, old_bin in enumerate(map(convert_bin, old_bins)):
                if not old_bin:
                    continue
                center = old_last_bin_end - old_bin_width*(i + 0.5)
                new_bin = int(math.floor(
                    (old_last_bin_end - center)/dv_desc.bin_width))
                if 0 <= new_bin < dv_desc.bin_count:
                    bins[new_bin] = ds_desc.keep_largest_func(
                        combine_bins(bins[new_bin], old_bin))
            return DataView(
                dv_desc, ds_desc, old_last_bin_end, bins)
        def get_dataview(ds_name, ds_desc, dv_name, dv_desc):
            if ds_name in obj:
                ds_data = obj[ds_name]
                if dv_name in ds_data:
                    dv_data = ds_data[dv_name]
                    if dv_data['bin_width'] == dv_desc.bin_width and len(dv_data['bins']) == dv_desc.bin_count:
                        return DataView(dv_desc, ds_desc, dv_data['last_bin_end'], list(map(convert_bin, dv_data['bins'])))
                    resized = resize_dataview(ds_desc, dv_desc, dv_data)
                    if resized is not None:
                        return resized
                if dv_name == 'last_twenty_years' and 'last_year' in ds_data:
                    resized = resize_dataview(
                        ds_desc, dv_desc, ds_data['last_year'])
                    if resized is not None:
                        return resized
            return new_dataview(ds_name, ds_desc, dv_name, dv_desc)
        return cls(dict(
            (ds_name, DataStream(ds_desc, dict(
                (dv_name, get_dataview(ds_name, ds_desc, dv_name, dv_desc))
                for dv_name, dv_desc in ds_desc.dataview_descriptions.items()
            )))
            for ds_name, ds_desc in datastream_descriptions.items()
        ))
    
    def __init__(self, datastreams):
        self.datastreams = datastreams
    
    def to_obj(self):
        return dict((ds_name, dict((dv_name, dict(last_bin_end=dv.last_bin_end, bin_width=dv.desc.bin_width, bins=dv.bins))
            for dv_name, dv in ds.dataviews.items())) for ds_name, ds in self.datastreams.items())


def make_multivalue_migrator(multivalue_keys, post_func=lambda bins: bins):
    def get_source_view(source, dv_name):
        source_view = source.get(dv_name)
        if source_view is None and dv_name == 'last_twenty_years':
            return source.get('last_year')
        return source_view

    def resize_source_view(source_view, dv_desc, last_bin_end):
        if source_view is None:
            return dict(last_bin_end=0, bins=dv_desc.bin_count*[{}])

        old_bins = source_view.get('bins')
        old_bin_width = source_view.get('bin_width')
        old_last_bin_end = source_view.get('last_bin_end')
        if (not old_bins or not old_bin_width or
                old_last_bin_end is None):
            return dict(last_bin_end=0, bins=dv_desc.bin_count*[{}])

        bins = dv_desc.bin_count*[{}]
        for i, old_bin in enumerate(old_bins):
            if isinstance(old_bin, dict):
                value = old_bin.get('null')
            else:
                total, count = old_bin
                value = (total.get('null') if isinstance(total, dict)
                         else total, count)
            if value is None:
                continue
            center = old_last_bin_end - old_bin_width*(i + 0.5)
            new_bin = int(math.floor(
                (last_bin_end - center)/dv_desc.bin_width))
            if 0 <= new_bin < dv_desc.bin_count:
                previous = bins[new_bin].get('null', (0, 0))
                bins[new_bin] = {
                    'null': (previous[0] + value[0],
                             previous[1] + value[1]),
                }
        return dict(last_bin_end=last_bin_end, bins=bins)

    def _(ds_name, ds_desc, dv_name, dv_desc, obj):
        if not obj:
            last_bin_end = 0
            bins = dv_desc.bin_count*[{}]
        else:
            source_views = dict(
                (key, get_source_view(
                    obj.get(source_name, {}), dv_name))
                for key, source_name in multivalue_keys.items())
            last_bin_end = max(
                [0] + [view.get('last_bin_end', 0)
                       for view in source_views.values()
                       if view is not None])
            if last_bin_end:
                last_bin_end = (math.ceil(
                    last_bin_end/dv_desc.bin_width) * dv_desc.bin_width)
            inputs = dict(
                (key, resize_source_view(
                    source_view, dv_desc, last_bin_end))
                for key, source_view in source_views.items())
            bins = post_func([dict((k, v['bins'][i]['null']) for k, v in inputs.items() if 'null' in v['bins'][i]) for i in range(dv_desc.bin_count)])
        return DataView(dv_desc, ds_desc, last_bin_end, bins)
    return _
