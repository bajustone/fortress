/** Core operators that all DatabaseAdapter implementations MUST support */
export type CoreOperator = '=' | '!=' | 'in' | 'gt' | 'lt' | 'gte' | 'lte';

export interface WhereClause {
  field: string;
  /**
   * Open string — core uses CoreOperator values.
   *  Adapters MAY support additional operators: 'like', 'isNull', 'between', etc.
   *  Adapters throw on unsupported operators at runtime.
   */
  operator: CoreOperator | (string & {});
  value: unknown;
}

/** Scope rules for row-level data isolation */
export interface ScopeRule {
  /** WHERE clauses auto-injected on findOne, findMany, count, update, delete */
  filters: WhereClause[];
  /** Default values auto-injected on create (e.g., { siteId: 3 }) */
  defaults: Record<string, unknown>;
}
