export interface IJobTitle {
  id?: string;
  name?: string;
  team_id?: string;
}

export interface IJobTitlesViewModel {
  total?: number;
  data?: IJobTitle[];
}
