"""Bounded, deterministic multidisciplinary evidence tools.

No eval, subprocess, network, repository execution, or side effects. Domain
signals are screening heuristics and are never presented as professional advice.
"""
from __future__ import annotations
import csv
import io
import json
import math
import re
from collections import Counter, defaultdict
from statistics import mean

DOMAIN_TOOLS = {
    'evidence.detect_context': {'description':'Detect candidate research domains from the actual contents of saved evidence', 'risk':'read_only'},
    'csv.data_quality': {'description':'Check missing cells, duplicate records and numeric-column coverage', 'risk':'read_only'},
    'csv.correlation': {'description':'Compute pairwise Pearson correlation for selected numeric CSV columns', 'risk':'read_only'},
    'csv.linear_model': {'description':'Fit a simple univariate least-squares line to numeric CSV columns', 'risk':'read_only'},
    'csv.finance_summary': {'description':'Calculate revenue, costs, gross difference and margin from explicit numeric columns', 'risk':'read_only'},
    'csv.group_summary': {'description':'Group and summarize a numeric CSV column by one category', 'risk':'read_only'},
    'json.numeric_summary': {'description':'Summarize a named numeric key from an array of JSON objects', 'risk':'read_only'},
    'text.security_indicators': {'description':'Screen source text for code patterns requiring security review (not vulnerability verification)', 'risk':'read_only'},
    'text.research_signals': {'description':'Identify explicit research-method terminology in text (not peer-review validation)', 'risk':'read_only'},
}
PARAMS = {
    'evidence.detect_context': (), 'csv.data_quality': (),
    'csv.correlation': ('x','y'), 'csv.linear_model': ('x','y'),
    'csv.finance_summary': ('revenue','cost'), 'csv.group_summary': ('group','value'),
    'json.numeric_summary': ('key',),
    'text.security_indicators': (), 'text.research_signals': (),
}

def validate_parameters(tool: str, params: dict) -> None:
    if tool not in PARAMS:raise ValueError('Unknown multidisciplinary tool')
    if not isinstance(params,dict) or set(params)!=set(PARAMS[tool]):
        raise ValueError('Parameters must be exactly: '+', '.join(PARAMS[tool]))
    for value in params.values():
        if not isinstance(value,str) or not value.strip() or len(value)>150:
            raise ValueError('Column or key names must be nonempty text (max 150 characters)')
    if 'x' in params and params['x']==params['y']:
        raise ValueError('Choose two different columns')
    if 'revenue' in params and params['revenue']==params['cost']:
        raise ValueError('Revenue and cost columns must be different')
    if 'group' in params and params['group']==params['value']:
        raise ValueError('Group and value columns must be different')

def _decode(raw):
    try:return raw.decode('utf-8-sig')
    except UnicodeDecodeError:raise ValueError('Source is not valid UTF-8 text')

def _csv(raw):
    text=_decode(raw)
    try:
        reader=csv.reader(io.StringIO(text,newline=''),strict=True)
        header=next(reader)
        if not (1<=len(header)<=100) or len(set(header))!=len(header) or any(not x.strip() for x in header):
            raise ValueError('CSV headers must be nonempty, unique and limited to 100')
        rows=[]
        for row in reader:
            if len(rows)>=10000:raise ValueError('CSV row limit exceeded (10000)')
            if len(row)!=len(header):raise ValueError('CSV row width mismatch')
            rows.append(row)
    except StopIteration:raise ValueError('Empty CSV')
    except csv.Error:raise ValueError('Malformed CSV')
    return header,rows

def _number(value):
    if not value.strip():return None
    try:out=float(value)
    except (ValueError,OverflowError):raise ValueError('Selected column contains non-numeric observations')
    if not math.isfinite(out):raise ValueError('Selected column contains non-finite observations')
    return out

def _column(header, name):
    if name not in header:raise ValueError('Column not found: '+name[:50])
    return header.index(name)

def _finite(x):
    if not math.isfinite(x):raise ValueError('Numerical overflow; rescale input data')
    return x

def _pairs(header,rows,params):
    a,b=_column(header,params['x']),_column(header,params['y']);values=[]
    for row in rows:
        x=_number(row[a]);y=_number(row[b]);
        if x is not None and y is not None:values.append((x,y))
    if len(values)<3:raise ValueError('At least three paired numeric observations are required')
    return values

def _correlation(values):
    xs,ys=zip(*values);mx=mean(xs);my=mean(ys)
    xx=_finite(math.fsum((x-mx)**2 for x in xs)); yy=_finite(math.fsum((y-my)**2 for y in ys))
    if xx==0 or yy==0:raise ValueError('Correlation is undefined for a constant column')
    xy=_finite(math.fsum((x-mx)*(y-my) for x,y in values))
    return max(-1,min(1,_finite(xy/math.sqrt(xx*yy)))),xx,xy,mx,my

def run_domain_tool(tool: str, raw: bytes, params: dict):
    validate_parameters(tool,params)
    if tool=='evidence.detect_context':
        sample=_decode(raw)[:160000].lower()
        dictionary={
           'finance':('revenue','expense','invoice','cash flow','balance sheet','gross margin'),
           'mathematics_and_data':('mean','variance','regression','dataset','correlation','standard deviation'),
           'scientific_research':('hypothesis','methodology','experiment','sample size','control group','peer review'),
           'cybersecurity':('vulnerability','authentication','cve-','threat','injection','firewall'),
           'software_engineering':('def ','function ','import ','class ','unit test','stack trace'),
           'robotics_and_engineering':('robot','torque','actuator','sensor','kinematics','velocity'),
           'earth_sciences':('geology','rainfall','erosion','seismic','soil profile','watershed'),
           'business_operations':('inventory','procurement','supply chain','customer','sales forecast','operations'),
        }
        scores=[{'domain':domain,'matched_indicators':[word for word in words if word in sample]} for domain,words in dictionary.items()]
        candidates=sorted(({'domain':x['domain'],'indicator_count':len(x['matched_indicators']),'indicators':x['matched_indicators']} for x in scores if x['matched_indicators']),key=lambda x:(-x['indicator_count'],x['domain']))
        return {'candidate_domains':candidates,'classification':'heuristic_content_screening','needs_human_review':True,
                'analyzed_characters':len(sample),'limitations':'Keywords can misclassify domains; no claim of comprehensive understanding or verified domain expertise.'}
    if tool.startswith('csv.'):
        header,rows=_csv(raw)
        if tool=='csv.data_quality':
            missing={name:sum(not row[i].strip() for row in rows) for i,name in enumerate(header)}
            duplicates=len(rows)-len({tuple(row) for row in rows})
            numeric={}
            for i,name in enumerate(header):
                count=0;bad=0
                for row in rows:
                    if not row[i].strip():continue
                    try:_number(row[i]);count+=1
                    except ValueError:bad+=1
                numeric[name]={'numeric_cells':count,'non_numeric_cells':bad}
            return {'rows':len(rows),'columns':len(header),'missing_by_column':missing,'duplicate_rows':duplicates,
                    'numeric_coverage':numeric,'limitations':'Descriptive quality checks only; duplicates may be legitimate.'}
        if tool in ('csv.correlation','csv.linear_model'):
            values=_pairs(header,rows,params)
            corr,xx,xy,mx,my=_correlation(values)
            if tool=='csv.correlation':return {'x':params['x'],'y':params['y'],'paired_rows':len(values),'excluded_rows':len(rows)-len(values),'pearson_r':corr,'limitations':'Correlation does not establish causation; results are descriptive and depend on supplied data.'}
            slope=_finite(xy/xx);intercept=_finite(my-slope*mx)
            return {'x':params['x'],'y':params['y'],'paired_rows':len(values),'excluded_rows':len(rows)-len(values),
                    'slope':slope,'intercept':intercept,'r_squared':_finite(corr*corr),
                    'limitations':'In-sample single-predictor fit only; not independently validated for prediction or causal inference.'}
        if tool=='csv.finance_summary':
            ir=_column(header,params['revenue']);ic=_column(header,params['cost']);revenues=[];costs=[]
            for row in rows:
                r=_number(row[ir]);c=_number(row[ic]);
                if r is not None and c is not None:revenues.append(r);costs.append(c)
            if not revenues:raise ValueError('No complete revenue/cost pairs')
            rev=_finite(math.fsum(revenues));cost=_finite(math.fsum(costs));difference=_finite(rev-cost)
            return {'revenue_column':params['revenue'],'cost_column':params['cost'],'included_rows':len(revenues),'excluded_rows':len(rows)-len(revenues),
                   'total_revenue':rev,'total_cost':cost,'gross_difference':difference,
                   'gross_margin_pct':_finite(100*difference/rev) if rev!=0 else None,
                   'negative_revenue_rows':sum(r<0 for r in revenues),'negative_cost_rows':sum(c<0 for c in costs),
                   'limitations':'Arithmetic only. Currency, accounting definitions, completeness and audit assurance are not verified.'}
        if tool=='csv.group_summary':
            ig=_column(header,params['group']);iv=_column(header,params['value']);groups=defaultdict(list);excluded=0
            for row in rows:
                value=_number(row[iv]);group=row[ig].strip()
                if value is None or not group:excluded+=1;continue
                groups[group].append(value)
                if len(groups)>100:raise ValueError('Group limit exceeded (100)')
            if not groups:raise ValueError('No grouped numeric observations')
            result=[{'group':k,'count':len(vals),'sum':_finite(math.fsum(vals)),'mean':_finite(math.fsum(vals)/len(vals))} for k,vals in sorted(groups.items())]
            return {'group_column':params['group'],'value_column':params['value'],'excluded_rows':excluded,'groups':result,'limitations':'Descriptive grouping only. No inference or causal analysis.'}
    if tool=='json.numeric_summary':
        try:obj=json.loads(_decode(raw),parse_constant=lambda v: (_ for _ in ()).throw(ValueError('Non-finite JSON constant')))
        except json.JSONDecodeError:raise ValueError('Invalid JSON')
        if not isinstance(obj,list) or len(obj)>10000:raise ValueError('Expected an array of at most 10000 objects')
        values=[]
        for item in obj:
            if not isinstance(item,dict):raise ValueError('Each record must be an object')
            v=item.get(params['key']);
            if v is None:continue
            if isinstance(v,bool) or not isinstance(v,(int,float)) or not math.isfinite(v):raise ValueError('Non-numeric or non-finite selected value')
            values.append(v)
        if not values:raise ValueError('No numeric values for selected key')
        return {'key':params['key'],'count':len(values),'missing':len(obj)-len(values),'sum':_finite(math.fsum(values)),
                'mean':_finite(math.fsum(values)/len(values)),'min':min(values),'max':max(values),
                'limitations':'Descriptive numerical summary; no schema or claim validation.'}
    if tool=='text.security_indicators':
        lines=_decode(raw).splitlines()
        patterns={
            'dynamic_code_evaluation':r'\b(?:eval|exec)\s*\(',
            'shell_process_flag':r'\bshell\s*=\s*True\b',
            'weak_hash_algorithm':r'\b(?:md5|sha1)\s*\(',
            'sql_string_interpolation':r'\b(?:SELECT|INSERT|UPDATE|DELETE)\b.{0,100}(?:\%s|\{\w+\})',
            'disabled_tls_verification':r'\bverify\s*=\s*False\b',
        }
        findings=[]
        for label,pattern in patterns.items():
            line_numbers=[i for i,line in enumerate(lines,1) if re.search(pattern,line,re.IGNORECASE)]
            if line_numbers:findings.append({'indicator':label,'occurrences':len(line_numbers),'line_numbers':line_numbers[:50],'truncated':len(line_numbers)>50})
        return {'lines_checked':len(lines),'findings':findings,'finding_type':'pattern_match_only',
                'limitations':'Neither findings nor their absence establish vulnerability or code safety. No code executed; no source excerpts returned.'}
    if tool=='text.research_signals':
        text=_decode(raw).lower()
        indicators={'hypothesis':r'\bhypothes[ie]s\b','methods':r'\bmethod(?:ology|s)?\b',
                    'sample':r'\b(?:sample size|participants|cohort)\b','controls':r'\b(?:control group|placebo|randomi[sz]ed)\b',
                    'limitations':r'\b(?:limitations|study limitations)\b','results':r'\bresults?\b',
                    'references':r'\b(?:references|bibliography|citations)\b'}
        return {'explicit_terms':[key for key,pat in indicators.items() if re.search(pat,text)],'missing_explicit_terms':[key for key,pat in indicators.items() if not re.search(pat,text)],
                'review_type':'terminology_screen_only','limitations':'Terms may be implied without keywords or appear without meaningful methodology. This is not a peer review.'}
    raise ValueError('Unsupported tool')
